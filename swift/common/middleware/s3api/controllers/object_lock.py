# Copyright (c) 2010-2023 OpenStack Foundation
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

from swift.common.utils import public

from swift.common.middleware.s3api.controllers.base import Controller, \
    bucket_operation, S3NotImplemented
from swift.common.middleware.s3api.s3response import \
    ObjectLockConfigurationNotFoundError
from swift.common.middleware.s3api.etree import Element, tostring, \
    fromstring, XMLSyntaxError, DocumentInvalid, SubElement


class ObjectLockController(Controller):
    """
    Handles GET object-lock request
    """
    @public
    @bucket_operation
    def GET(self, req):
        """
        Handles GET object-lock param calls.
        """
        sysmeta = req.get_container_info(self.app).get('sysmeta', {})

        root = Element('ObjectLockConfiguration')
        if sysmeta.get('lock-enabled'):
            SubElement(root, 'ObjectLockEnabled').text = 'Enabled'
            mode = sysmeta.get('lock-mode')
            if mode:
                rule = SubElement(SubElement(root, 'Rule'), 'DefaultRetention')
                SubElement(rule, 'Mode').text = mode.upper()

                days = sysmeta.get('lock-days')
                if days:
                    SubElement(rule, 'Days').text = days
                years = sysmeta.get('lock-years')
                if years:
                    SubElement(rule, 'Years').text = years
        else:
            raise ObjectLockConfigurationNotFoundError(req.container_name)

        body = tostring(root)

        return HTTPOk(body=body, content_type=None)

    @public
    @bucket_operation
    def PUT(self, req):
        """
        Handles PUT object-lock param calls.
        """
        if 'object_locking' not in get_swift_info():
            raise S3NotImplemented('The requested resource is not implemented')
        
        xml = req.xml(MAX_PUT_VERSIONING_BODY_SIZE)
        try:
            root = fromstring(xml, 'ObjectLockConfiguration')
            enabled = root.find('./ObjectLockEnabled').text
            rule = root.find('./Rule/DefultRetention')
            if rule:
                days = rule.find('./Days')
                if days:
                    req.headers['X-Container-Lock-Days'] = days.text
                years = rule.find('./Years')
                if years:
                    req.headers['X-Container-Lock-Years'] = years.text
                mode = rule.find('./Mode')
                if mode:
                    req.headers['X-Container-Lock-Mode'] = mode.text
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            self.logger.error(e)
            raise

        req.headers['X-Container-Lock-Enabled'] = enabled or 'Disabled'
        req.get_response(self.app, 'POST')

        return HTTPOk()
        
