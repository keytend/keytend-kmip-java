#!/usr/bin/env bash
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

set -euo pipefail
# Set JDK17_HOME, JDK21_HOME and JDK25_HOME for non-SDKMAN installations.
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
mkdir -p .cache
log_kind=unit-final
if [[ " $* " == *"-Pintegration"* ]]; then log_kind=integration; fi
for version in 17 21 25; do
  var="JDK${version}_HOME"
  jdk_path="${!var:-}"
  if [[ -z "$jdk_path" ]]; then
    # The newest patch release SDKMAN has (version order, not name order: 21.0.13 after 21.0.4).
    while IFS= read -r candidate; do
      if [[ -x "$candidate/bin/java" ]]; then jdk_path="$candidate"; fi
    done < <(printf '%s\n' "$HOME"/.sdkman/candidates/java/"$version".* | sort -V)
  fi
  [[ -x "$jdk_path/bin/java" ]] || { echo "Set $var to a JDK $version installation" >&2; exit 1; }
  JAVA_HOME="$jdk_path" PATH="$jdk_path/bin:$PATH" ./mvnw -B verify "$@" 2>&1 | tee ".cache/${log_kind}-jdk${version}.log"
done
