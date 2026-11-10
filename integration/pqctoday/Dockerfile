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

# The server links glibc and OpenSSL dynamically, so it builds on UBI 9 itself (glibc 2.34) with
# the pinned Rust from rustup; UBI 9's own Rust (1.92) is older than the toolchain the lab pins.
FROM registry.access.redhat.com/ubi9/ubi:9.8-1793861509@sha256:1963e00991088221a3405be7eb315a3dbc0be0f1f7440f0bd537d481cf33c83e AS build
ARG PQCTODAY_COMMIT=010da23173bd39a57113fe8f5e9466981a52e27c
ARG RUST_VERSION=1.99.1
ARG RUSTUP_VERSION=1.29.3
ARG RUSTUP_SHA256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
RUN dnf -y --setopt=install_weak_deps=0 install cmake clang clang-devel gcc gcc-c++ make openssl-devel pkgconf-pkg-config perl-FindBin perl-IPC-Cmd && dnf clean all
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL -o /tmp/rustup-init https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init \
 && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain ${RUST_VERSION} && rm /tmp/rustup-init
RUN curl -fsSL https://codeload.github.com/pqctoday-org/pqctoday-hsm/tar.gz/${PQCTODAY_COMMIT} | tar xz -C /opt && mv /opt/pqctoday-hsm-* /opt/pqctoday
WORKDIR /opt/pqctoday/kmip
RUN cargo build --locked --release --bin pqctoday-kmip -j 4
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.8-1793862054@sha256:4b79c93106c14ad1c234907f83441ff0e4f8d24e78426a36e159098e9f7e6fa5
RUN microdnf -y --setopt=install_weak_deps=0 install ca-certificates openssl-libs && microdnf clean all
COPY --from=build /opt/pqctoday/kmip/target/release/pqctoday-kmip /usr/local/bin/
COPY --from=build /opt/pqctoday/LICENSE /usr/share/licenses/pqctoday/LICENSE
USER 65534:65534
EXPOSE 5696
ENTRYPOINT ["pqctoday-kmip", "--listen", "0.0.0.0:5696", "--store", "/tmp/kmip.sqlite", "--engine-store", "/tmp/kmip-engine", "--enable-interop", "--tls-cert", "/certs/server.pem", "--tls-key", "/certs/server-key.pem", "--tls-client-ca", "/certs/ca.pem", "--ca-key", "urn:keytend:test-ca-key", "--ca-cert", "urn:keytend:test-ca-cert"]
