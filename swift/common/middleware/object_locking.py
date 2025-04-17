# Copyright (c) 2025 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift.common.swob import HTTPForbidden, HTTPBadRequest, wsgify
from swift.common.utils import get_logger, split_path, config_true_value, get_swift_info
from swift.proxy.controllers.base import get_container_info, get_object_info
from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.utils.timestamp import Timestamp
from swift.common.middleware.versioned_writes.object_versioning import CLIENT_VERSIONS_ENABLED

"""
Locks objects
"""

DAY_OFFSET = 24 * 60 * 60
YEAR_OFFSET = DAY_OFFSET * 365

LOCK_ENABLED = 'enabled'
LOCK_MODE = 'mode'
LOCK_DAYS = 'days'
LOCK_YEARS = 'years'
LOCK_LEGAL = 'legalhold'
LOCK_UNTIL = 'lockeduntil'


def usr_header(name, obj=False):
    obj_type = 'Object' if obj else 'Container'
    return f'X-{obj_type}-Lock-{name}'


def sys_header(name, obj=False):
    sys_prefix = get_sys_meta_prefix('object') if obj \
        else get_sys_meta_prefix('container')
    return f'{sys_prefix}lock-{name.lower()}'


def parse_duration(duration):
    """
    Takes a single str and parses it as a lock duration, raises a ValueError
    if invalid. 0 and '' are valid and returned as 0. Negative numbers
    are invalid. All other integers are valid.

    :returns: the parsed duration
    """
    if duration == '':
        return 0
    duration_num = 0
    try:
        duration_num = int(duration)
    except ValueError:
        raise HTTPBadRequest(
            f'''{duration} is not a valid lock duration,
            must be a positive integer.'''
        )
    if duration_num < 0:
        raise HTTPBadRequest("Lock duration cannot be negative")
    return duration_num


def get_lock_duration(days_str, years_str):
    days = parse_duration(days_str)
    years = parse_duration(years_str)
    if days > 0 and years > 0:
        raise HTTPBadRequest('Cannot set both Days and Years lock duration.')
    if days > 0:
        return (days, LOCK_DAYS)
    if years > 0:
        return (years, LOCK_YEARS)

    return (0, None)


def validate_mode(mode):
    if mode is None:
        return None

    m = mode.lower()
    if m == 'governance' or m == 'compliance':
        return m
    else:
        raise HTTPBadRequest(
            f'''Value of Lock Mode header is invalid, must
            be Governance or Compliance if present, was "{mode}".'''
        )


def is_container_lock_enabled(headers, container_meta):
    currently_enabled = config_true_value(container_meta.get(LOCK_ENABLED))
    user_enabled = config_true_value(headers.get(usr_header(LOCK_ENABLED)))

    if currently_enabled and not user_enabled:
        raise HTTPBadRequest(
            'Cannot disable container locking once enabled')

    if not currently_enabled:
        currently_enabled = user_enabled

    return currently_enabled


def write_sys_headers(r, enabled, mode, time_type, lock_duration, obj):
    if not enabled:
        return

    r.headers[CLIENT_VERSIONS_ENABLED] = 'true'
    r.headers[sys_header(LOCK_ENABLED, obj=obj)] = 'true'

    r.headers[sys_header(LOCK_MODE, obj=obj)] = mode

    if time_type:
        r.headers[sys_header(time_type, obj=obj)] = lock_duration


def write_usr_headers(r):
    for h in [LOCK_ENABLED, LOCK_MODE, LOCK_DAYS, LOCK_YEARS, LOCK_UNTIL]:
        for obj in [True, False]:
            if sys_header(h, obj=obj) in r.headers:
                r.headers[usr_header(h, obj=obj)
                          ] = r.headers[sys_header(h, obj=obj)]


class ObjectLockingMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route='object locking')

    @wsgify
    def __call__(self, req):
        version, account, container, obj = self.get_dest_details(req)

        container_info = get_container_info(
            req.environ, self.app, swift_source='OL')

        container_meta = container_info['sysmeta']
        locked = is_container_lock_enabled(req.headers, container_meta)

        # If lock isn't enabled for the container we don't need to do anything
        if not locked:
            return req.get_response(self.app)

        user_groups = (req.remote_user or '').split(',')
        account_user = user_groups[1] if len(user_groups) > 1 else None

        def_lock_mode = validate_mode(req.headers.get(usr_header(LOCK_MODE)))
        if def_lock_mode is None:
            if LOCK_MODE in container_meta:
                def_lock_mode = container_meta.get(LOCK_MODE)

        def_lock_duration, def_time_type = get_lock_duration(req.headers.get(usr_header(
            LOCK_DAYS), ''), req.headers.get(usr_header(LOCK_YEARS), ''))
        if def_time_type is None:
            def_lock_duration, def_time_type = get_lock_duration(
                container_meta.get(LOCK_DAYS, ''), container_meta.get(LOCK_YEARS, ''))

        if (def_lock_mode is None) != (def_time_type is None):
            raise HTTPBadRequest(
                'Must set both default lock mode and duration.')

        container_has_defaults = def_lock_mode is not None

        # Because containers must be empty to be deleted, there are no
        # non-object API calls that we will fail. Just add sysmeta to response
        if obj is None:
            if req.method in ('POST', 'PUT', 'COPY'):
                write_sys_headers(req, locked, def_lock_mode, def_time_type,
                                  def_lock_duration, obj=False)

            resp = req.get_response(self.app)

            write_usr_headers(resp)

            return resp

        # Because COPY requests need to check if the destination is locked
        # we can't use the request's path here, so we construct our own
        obj_info = get_object_info(
            req.environ, self.app, path=f'/{version}/{account}/{container}/{obj}', swift_source='OL'
        )
        obj_meta = obj_info.get('sysmeta', {})

        is_locked = obj_meta.get(LOCK_UNTIL) is not None

        obj_lock_enabled = req.headers.get(usr_header(LOCK_ENABLED, obj=True))
        if obj_lock_enabled is None:
            if LOCK_ENABLED in obj_meta:
                obj_lock_enabled = obj_meta[LOCK_ENABLED]

        obj_lock_mode = validate_mode(
            req.headers.get(usr_header(LOCK_MODE, obj=True)))
        if obj_lock_mode is None:
            if LOCK_MODE in obj_meta:
                obj_lock_mode = obj_meta.get(LOCK_MODE)

        obj_lock_duration, obj_time_type = get_lock_duration(req.headers.get(usr_header(
            LOCK_DAYS, obj=True), ''), req.headers.get(usr_header(LOCK_YEARS, obj=True), ''))
        if obj_time_type is None:
            obj_lock_duration, obj_time_type = get_lock_duration(obj_meta.get(
                LOCK_DAYS, ''), obj_meta.get(LOCK_YEARS, ''))

        lock_mode = (obj_lock_mode if obj_lock_mode else def_lock_mode)
        lock_duration, time_type = ((obj_lock_duration, obj_time_type) if obj_time_type else (
            def_lock_duration, def_time_type))

        if (lock_mode is None) != (time_type is None):
            raise HTTPBadRequest('Must set both object lock mode and duration.')

        should_lock_obj = lock_mode is not None or container_has_defaults

        versioned_req = req.params.get('version-id') is not None

        if versioned_req and req.method == 'DELETE':
            obj_lock_enabled = obj_meta.get(LOCK_ENABLED)
            locked_until = obj_meta.get(LOCK_UNTIL, 0.0)
            if obj_lock_enabled and Timestamp.now() < Timestamp(locked_until):
                raise HTTPBadRequest(
                    'You specifically told us not to let you do this.'
                )  # TODO: Handle modes

        if not versioned_req and req.method in ('POST', 'PUT', 'COPY') and should_lock_obj:
            offset = def_lock_duration * \
                (DAY_OFFSET if def_time_type == LOCK_DAYS else YEAR_OFFSET)
            unlock_ts = Timestamp(Timestamp.now().timestamp + offset)
            req.headers[sys_header(LOCK_UNTIL, obj=True)] = unlock_ts.isoformat

        write_sys_headers(req, locked, def_lock_mode, def_time_type,
                          def_lock_duration, obj=False)
        write_sys_headers(req, should_lock_obj, lock_mode,
                          time_type, lock_duration, obj=True)

        resp = req.get_response(self.app)

        write_usr_headers(resp)

        return resp

    def get_dest_details(self, req):
        # Get the request destination to check lock status
        try:
            version, account, container, obj = req.split_path(
                3, 4, rest_with_last=True)
            if req.method == 'COPY':
                account = req.headers.get('Destination-Account', account)
                container, obj = split_path(
                    req.headers.get('Destination'), 2, 2, rest_with_last=True
                )

            return (version, account, container, obj)
        except ValueError:
            return (None, None, None, None)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def object_locking_filter(app):
        if 'object_versioning' not in get_swift_info():
            raise ValueError('object locking requires object_versioning')
        return ObjectLockingMiddleware(app, conf)

    return object_locking_filter
