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
from swift.common.utils import get_logger, split_path
from swift.proxy.controllers.base import get_container_info, get_object_info
from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.utils.timestamp import Timestamp

"""
Locks objects
"""

DAY_OFFSET = 24 * 60 * 60
YEAR_OFFSET = DAY_OFFSET * 365.25  # TODO: Better leap year handling?

LOCK_ENABLED = 'Enabled'
LOCK_MODE = 'Mode'
LOCK_DAYS = 'Days'
LOCK_YEARS = 'Years'
LOCK_UNTIL = 'LockedUntil'


def usr_header(name, for_obj=False):
    obj_type = 'Object' if for_obj else 'Container'
    return f'X-{obj_type}-Lock-{name}'


def sys_header(name, for_obj=False):
    sys_prefix = get_sys_meta_prefix('object') if for_obj \
        else get_sys_meta_prefix('container')
    return f'{sys_prefix}-Lock-{name}'


def parse_duration(duration):
    """
    Takes a single str and parses it as a lock duration, raises a ValueError
    if invalid. 0 and '' are valid and returned as 0. Negative numbers
    are invalid. All other integers are valid.

    :returns: the parsed duration
    """
    if duration == "":
        return 0
    duration_num = 0
    try:
        duration_num = int(duration)
    except ValueError:
        raise ValueError(
            f'''{duration} is not a valid lock duration,
            must be a positive integer.'''
        )
    if duration_num < 0:
        raise ValueError("Lock duration cannot be negative")
    return duration_num


class LockSettings(object):
    def __init__(self, enabled, mode, days, years, store_days,
                 store_years, until, locked_obj):
        types_valid = (
            isinstance(enabled, str)
            and isinstance(mode, str)
            and isinstance(days, str)
            and isinstance(years, str)
            and isinstance(store_days, str)
            and isinstance(store_years, str)
            and isinstance(until, str)
            and isinstance(locked_obj, str)
        )
        if not types_valid:
            raise Exception(
                'Invalid lock settings input, this should never happen')

        self.locked_obj = locked_obj

        if enabled == 'Enabled':
            self.enabled = 'Enabled'
        elif enabled == '':
            # If object locking is disabled we default all relevent settings
            # and return early. We can't warn the user if they try and set
            # other settings, but we can't do that anyway
            self.enabled = ''
            self.mode = ''
            self.days = ''
            self.years = ''
            return
        else:
            raise ValueError(
                f'''Value of X-{locked_obj}-Lock-Enabled header is invalid,
                  must be Enabled or empty string, was "{enabled}".'''
            )

        if mode == 'Governance' or mode == 'Compliance':
            self.mode = mode
        else:
            raise ValueError(
                f'''Value of X-{locked_obj}-Lock-Mode header is invalid, must
                be Governance or Compliance, was "{mode}".'''
            )

        # If we haven't been given a new duration, we use the old one as long
        # as it exists. We assume it's valid here because we must have
        # checked it in the past (barring admin nonsense, their fault for now)
        num_days = parse_duration(days)
        num_years = parse_duration(years)

        if not num_days and not num_years and (store_days or store_years):
            self.days = store_days
            self.years = store_years
        elif num_days and num_years:
            raise ValueError(
                f'''Cannot set both X-{locked_obj}-Lock-Days and
                X-{locked_obj}-Lock-Years headers, consider using only days.'''
            )
        elif num_days:
            self.days = str(num_days)
            self.years = ''
        elif num_years:
            self.days = ''
            self.years = str(num_years)
        else:
            raise ValueError(
                f'''No lock duration, set one of X-{locked_obj}-Lock-Days
                or X-{locked_obj}-Lock-Years headers.'''
            )

    def update_headers(self, req):
        # There is no scenario where we want to write headers if locking is off
        if not self.enabled:
            return

        for_obj = self.locked_obj == 'Object'
        vals = [(self.enabled, LOCK_ENABLED), (self.mode, LOCK_MODE),
                (self.days, LOCK_DAYS), (self.years, LOCK_YEARS)]

        for val, header in vals:
            if not val:
                continue

            req.headers[usr_header(header, for_obj)] = val
            req.headers[sys_header(header, for_obj)] = val

    def unlock_timestamp(self):
        offset = (
            int(self.days) *
            DAY_OFFSET if self.days else int(self.years) * YEAR_OFFSET
        )
        return Timestamp(Timestamp.now().timestamp + offset)


class ObjectLockingMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route='object locking')

    @wsgify
    def __call__(self, req):
        version, account, container, obj = self.get_dest_details(req)

        container_info = get_container_info(
            req.environ, self.app, swift_source='OL')
        # Because COPY requests need to check if the destination is locked
        # we can't use the request's path here, so we construct our own
        obj_info = get_object_info(
            self.app, req.environ, f'/{version}/{account}/{container}/{obj}'
        )

        # TODO: Catch value err here
        try:
            container_cfg = self.verify_and_update_container_lock(
                req, container_info
            )
        except ValueError as e:
            return HTTPBadRequest(body=e.args[0])

        container_cfg.update_headers(req)

        # TODO: Bucket settings

        if req.method in ('PUT', 'POST', 'DELETE'):
            if obj_info:
                locked_until = obj_info['sysmeta'] \
                    .get(sys_header(LOCK_UNTIL, for_obj=True))

                if Timestamp.now() < Timestamp(locked_until):
                    return HTTPForbidden(
                        body='You specifically told us not to let you do this.'
                    )  # TODO: Handle modes
            else:
                req[sys_header(LOCK_UNTIL)] = \
                    container_cfg.unlock_timestamp()

        resp = req.get_response(self.app)
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

    def get_container_lock_settings(self, req, container_info):
        enabled = container_info['sysmeta'].get(sys_header(LOCK_ENABLED), '')

        if not enabled:
            enabled = req.headers.get(usr_header(LOCK_ENABLED), '')

        container_mode = container_mode = req.headers.get(
            usr_header(LOCK_MODE),
            container_info['sysmeta'].get(sys_header(LOCK_MODE), ''),
        )
        days = req.headers.get(usr_header(LOCK_DAYS), '')
        years = req.headers.get(usr_header(LOCK_YEARS), '')
        store_days = container_info['sysmeta'].get(sys_header(LOCK_DAYS), '')
        store_years = container_info['sysmeta'].get(sys_header(LOCK_YEARS), '')

        return LockSettings(
            enabled,
            container_mode,
            days,
            years,
            store_days,
            store_years,
            'Container',
        )


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def object_locking_filter(app):
        return ObjectLockingMiddleware(app, conf)

    return object_locking_filter
