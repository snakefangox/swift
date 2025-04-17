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

import time
import unittest
from swift.common import swob
from swift.common.swob import Request, str_to_wsgi
from swift.common.request_helpers import get_reserved_name
from test.unit.common.middleware.helpers import FakeSwift
from swift.common.utils.timestamp import Timestamp
from swift.common.middleware import versioned_writes, copy, symlink, \
    object_locking


class FakeCache(object):
    def __init__(self, val):
        self.val = {'sysmeta': val}

    def get(self, *args):
        return self.val

    def set(self, *args, **kwargs):
        pass


class ObjectLockingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = FakeSwift()
        conf = {'allow_object_versioning': 'true'}
        self.sym = symlink.filter_factory(conf)(self.app)
        self.sym.logger = self.app.logger
        self.ov = versioned_writes.object_versioning.\
            ObjectVersioningMiddleware(self.sym, conf)
        self.ov.logger = self.app.logger
        self.cp = copy.filter_factory({})(self.ov)
        self.ol = object_locking.ObjectLockingMiddleware(self.cp, conf)

        # Container case
        self.app.register('GET', '/v1/a', swob.HTTPOk, {}, '')
        self.app.register('GET', '/v1/a/c', swob.HTTPOk, {}, '')
        self.app.register('PUT', '/v1/a/c', swob.HTTPOk, {}, 'passed')
        self.app.register('PUT', '/v1/a/\x00versions\x00c',
                          swob.HTTPOk, {}, 'passed')
        # Object cases
        self.app.register('GET', '/v1/a/c/o', swob.HTTPOk, {}, '')
        self.app.register('PUT', '/v1/a/c/o', swob.HTTPOk, {}, 'passed')

    def test_create_container(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
            'X-Container-Lock-Days': '6',
        }
        req = Request.blank('/v1/a/c',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)

        for h, v in lock_headers.items():
            self.assertIn(h, res.headers)
            self.assertEqual(v, res.headers[h])

    def test_create_container_years(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
            'X-Container-Lock-Years': '2',
        }
        req = Request.blank('/v1/a/c',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)

        for h, v in lock_headers.items():
            self.assertIn(h, res.headers)
            self.assertEqual(v, res.headers[h])

    def test_create_container_no_mode(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Days': '6',
        }
        req = Request.blank('/v1/a/c',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 400)

    def test_create_container_no_time(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
        }
        req = Request.blank('/v1/a/c',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 400)

    def test_create_container_two_times(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
            'X-Container-Lock-Days': '6',
            'X-Container-Lock-Years': '2',
        }
        req = Request.blank('/v1/a/c',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 400)

    def test_create_object(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
            'X-Container-Lock-Days': '6',
        }
        req = Request.blank('/v1/a/c/o',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)

        for h, v in lock_headers.items():
            self.assertIn(h, res.headers)
            self.assertEqual(v, res.headers[h])

    def test_create_object_partial(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
        }
        req = Request.blank('/v1/a/c/o',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 400)

    def test_create_object_partial_defaulted(self):
        lock_headers = {
            'X-Container-Lock-Enabled': 'true',
            'X-Container-Lock-Mode': 'compliance',
            'X-Container-Lock-Days': '6',
            'X-Object-Lock-Days': '17',
        }
        req = Request.blank('/v1/a/c/o',
                            headers=lock_headers,
                            environ={'REQUEST_METHOD': 'PUT'})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['X-Object-Lock-Days'], '17')

    def test_delete_object_locked(self):
        self.app.register_next_response(
            'DELETE', '/v1/a/c/o', swob.HTTPOk, {}, 'locked')
        cache = FakeCache({'versions-enabled': 'true',
                           'versions-container': 'tc',
                           'lock-enabled': 'true',
                           'lock-mode': 'Governance',
                           'lock-days': '3'})
        info_cache = {'object/a/c/o': {'sysmeta': {
            'lock-enabled': 'true',
            'lock-mode': 'Governance',
            'lock-days': '3',
            'lock-lockeduntil': f'{time.time() + 1000}'}}}
        req = Request.blank('/v1/a/c/o',
                            headers={},
                            environ={'REQUEST_METHOD': 'DELETE', 'swift.cache': cache,
                                     'swift.infocache': info_cache})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)

    def test_delete_object_version_locked(self):
        self.app.register_next_response(
            'DELETE', '/v1/a/c/o?version-id=194837', swob.HTTPOk, {}, 'locked')
        cache = FakeCache({'lock-enabled': 'true',
                           'versions-enabled': 'true',
                           'lock-mode': 'Governance',
                           'lock-days': '3'})
        info_cache = {'object/a/c/o': {'sysmeta': {
            'lock-enabled': 'true',
            'lock-mode': 'Governance',
            'lock-days': '3',
            'lock-lockeduntil': f'{time.time() + 1000}'}}}
        req = Request.blank('/v1/a/c/o?version-id=194837',
                            headers={},
                            environ={'REQUEST_METHOD': 'DELETE', 'swift.cache': cache,
                                     'swift.infocache': info_cache})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 400)

    def test_delete_solo_object_version_locked(self):
        self.app.register_next_response(
            'DELETE', '/v1/a/c/o?version-id=194837', swob.HTTPOk, {}, 'locked')
        cache = FakeCache({'versions-enabled': 'true',
                           'versions-container': get_reserved_name('versions', 'v'),
                          'lock-enabled': 'true'})
        info_cache = {'object/a/c/o': {'sysmeta': {
            'lock-enabled': 'true',
            'lock-mode': 'Governance',
            'lock-days': '3',
            'lock-lockeduntil': f'{time.time() + 1000}'}}}
        req = Request.blank('/v1/a/c/o?version-id=194837',
                            headers={},
                            environ={'REQUEST_METHOD': 'DELETE', 'swift.cache': cache,
                                     'swift.infocache': info_cache})
        res = req.get_response(self.ol)
        print(res.body)
        self.assertEqual(res.status_int, 400)

    def test_delete_object_unlocked(self):
        self.app.register_next_response(
            'DELETE', '/v1/a/c/o', swob.HTTPOk, {}, 'locked')
        cache = FakeCache({'versions-enabled': 'true',
                           'lock-enabled': 'true',
                           'lock-mode': 'Governance',
                           'lock-days': '3'})
        info_cache = {'object/a/c/o': {'sysmeta': {
            'lock-enabled': 'true',
            'lock-mode': 'Governance',
            'lock-days': '3',
            'lock-lockeduntil': f'{time.time() - 1000}'}}}
        req = Request.blank('/v1/a/c/o',
                            headers={},
                            environ={'REQUEST_METHOD': 'DELETE', 'swift.cache': cache,
                                     'swift.infocache': info_cache})
        res = req.get_response(self.ol)
        self.assertEqual(res.status_int, 200)
