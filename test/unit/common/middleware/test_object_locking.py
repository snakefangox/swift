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

import unittest
from swift.common import swob
from swift.common.swob import Request
from test.unit.common.middleware.helpers import FakeSwift
from swift.common.middleware import versioned_writes, copy, symlink, \
    object_locking


class ObjectLockingTestCase(unittest.TestCase):
    def setUp(self):
        self.app = FakeSwift()
        # self.sym = symlink.filter_factory({})(self.app)
        # self.sym.logger = self.app.logger
        # self.ov = versioned_writes.object_versioning.\
        #     ObjectVersioningMiddleware(self.sym, {})
        # self.ov.logger = self.app.logger
        # self.cp = copy.filter_factory({})(self.ov)
        self.ol = object_locking.filter_factory({})(self.app)

    def test_create_container(self):
        self.app.register('HEAD', '/v1/a', swob.HTTPOk, {}, '')
        self.app.register('HEAD', '/v1/a/c', swob.HTTPOk, {}, '')
        self.app.register('PUT', '/v1/a/c', swob.HTTPOk, {}, 'passed')
        req = Request.blank('/v1/a/c',
                            headers={'X-Versions-Enabled': 'true'},
                            environ={'REQUEST_METHOD': 'PUT'})
        res = self.ol(req.environ, {})
        print(res)
