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

# Python 3.12 from UBI 9's own packages; python is linked to it for the entrypoint and the lab's
# administrative commands.
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1793862054@sha256:4b79c93106c14ad1c234907f83441ff0e4f8d24e78426a36e159098e9f7e6fa5
ARG PYKMIP_COMMIT=481563735cc96eb9f7b363df3c24b2ea68b9353f
RUN microdnf -y --setopt=install_weak_deps=0 install python3.12 python3.12-pip tar gzip && microdnf clean all \
 && ln -s /usr/bin/python3.12 /usr/local/bin/python
RUN curl -fsSL https://codeload.github.com/OpenKMIP/PyKMIP/tar.gz/${PYKMIP_COMMIT} | tar xz -C /opt && mv /opt/PyKMIP-* /opt/pykmip
RUN python -m pip install --no-cache-dir cryptography==50.0.2 SQLAlchemy==2.1.8 enum-compat==0.0.3 requests==2.34.2 six==1.17.0 && python -m pip install --no-cache-dir --no-deps /opt/pykmip
COPY server.py /opt/server.py
EXPOSE 5696
ENTRYPOINT ["python", "/opt/server.py"]
