# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from kmip.services.server import KmipServer
from pathlib import Path
import json


def main():
    Path("/tmp/policies").mkdir(exist_ok=True)
    # Explicit per-object sharing policies, selected by disposable fixture administration (the attribute is server-managed).
    policies = {}
    for name, get, locate in [("catalog-shared", "ALLOW_ALL", "ALLOW_OWNER"),
                              ("catalog-list-only", "ALLOW_OWNER", "ALLOW_ALL")]:
        policies[name] = {"preset": {"SYMMETRIC_KEY": {
            "GET": get, "LOCATE": locate, "GET_ATTRIBUTES": "ALLOW_OWNER",
            "GET_ATTRIBUTE_LIST": "ALLOW_OWNER", "MODIFY_ATTRIBUTE": "ALLOW_OWNER",
            "ACTIVATE": "ALLOW_OWNER", "REVOKE": "ALLOW_OWNER", "DESTROY": "ALLOW_OWNER"}}}
    Path("/tmp/policies/catalog.json").write_text(json.dumps(policies))
    Path("/opt/server.conf").write_text("[server]\nhostname=0.0.0.0\nport=5696\ncertificate_path=/certs/server.pem\nkey_path=/certs/server-key.pem\nca_path=/certs/ca.pem\nauth_suite=TLS1.2\n")
    server = KmipServer(hostname='0.0.0.0', port=5696,
        certificate_path='/certs/server.pem', key_path='/certs/server-key.pem',
        ca_path='/certs/ca.pem', auth_suite='TLS1.2',
        config_path='/opt/server.conf', log_path='/tmp/pykmip.log',
        policy_path='/tmp/policies', enable_tls_client_auth=True,
        tls_cipher_suites='ECDHE-RSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256',
        logging_level='INFO', database_path='/tmp/pykmip.db')
    with server:
        server.serve()


# PyKMIP's server starts a multiprocessing Manager. From Python 3.14 the Linux default start
# method is forkserver, which imports this file again in the child, so the server starts only
# from the main module.
if __name__ == "__main__":
    main()
