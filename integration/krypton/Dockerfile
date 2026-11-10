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

# The binary is static (CGO_ENABLED=0), so it builds on the Go image and runs on UBI 9 micro.
FROM docker.io/library/golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
ARG KRYPTON_COMMIT=7ca8dc58615f506b8ce7e9359e625df5cf72a7e5
RUN curl -fsSL https://codeload.github.com/openkcm/krypton/tar.gz/${KRYPTON_COMMIT} | tar xz -C /opt && mv /opt/krypton-* /opt/krypton
WORKDIR /opt/krypton
COPY bootstrap.go ./catalog-fixture/main.go
ENV GOEXPERIMENT=runtimesecret
RUN CGO_ENABLED=0 go build -o /krypton ./catalog-fixture
FROM registry.access.redhat.com/ubi9/ubi-micro:9.8-1793860449@sha256:6d9eff186ce3ccf399c1835265e7fd3f83bd112cc3422da2d39fd44e234aab59
COPY --from=build /krypton /usr/local/bin/krypton
COPY --from=build /opt/krypton/LICENSE /usr/share/licenses/krypton/LICENSE
COPY --from=build /opt/krypton/catalog-fixture/main.go /usr/share/doc/krypton/catalog-fixture.go
USER 65534:65534
EXPOSE 5696
ENTRYPOINT ["krypton"]
