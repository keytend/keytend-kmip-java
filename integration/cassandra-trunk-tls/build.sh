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

# Builds the Cassandra trunk TLS sample against a built Cassandra trunk checkout and the SDK JAR,
# runs its standalone tests, and (with --install) puts both JARs on that checkout's classpaths
# and its Cassandra-side tests in its test tree.
#
#   integration/cassandra-trunk-tls/build.sh CASSANDRA_DIR SDK_JAR [--install]
#
# CASSANDRA_DIR must have run `ant jar build-test` on JDK 17 or later. Nothing is written to it
# without --install.
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 CASSANDRA_DIR SDK_JAR [--install]" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
cassandra=$(cd "$1" && pwd)
sdk=$(readlink -f "$2")
install=${3:-}
# The in-memory KMIP server (keytend-kmip-testing) is for the tests only: never on the adapter's
# class path or a node's. By default, the one this repository built for the SDK JAR's version.
version=$(basename "$sdk" .jar)
version=${version#keytend-kmip-}
testing=${KEYTEND_TESTING_JAR:-$here/../../testing/target/keytend-kmip-testing-$version.jar}
[ -f "$testing" ] || { echo "no keytend-kmip-testing JAR at $testing (./mvnw -pl testing -am package -DskipTests," \
  "or set KEYTEND_TESTING_JAR)" >&2; exit 2; }
testing=$(readlink -f "$testing")
javac=${JAVA_HOME:+$JAVA_HOME/bin/}javac
jar=${JAVA_HOME:+$JAVA_HOME/bin/}jar
java=${JAVA_HOME:+$JAVA_HOME/bin/}java

cassandra_jar=$(find "$cassandra/build" -maxdepth 1 -name 'apache-cassandra-*.jar' \
  ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1)
[ -n "$cassandra_jar" ] || { echo "no Cassandra JAR in $cassandra/build: run ant jar" >&2; exit 1; }
cp_libs=$(find "$cassandra/build/lib/jars" -name '*.jar' ! -name 'keytend-kmip-*' ! -name 'keytend-kmip-cassandra-*' | sort | tr '\n' ':')

out="$here/target"
rm -rf "$out"
mkdir -p "$out/classes" "$out/test-classes"
# -path: the Class-Path entries of some third-party JARs' manifests name JARs Cassandra does not ship
"$javac" --release 17 -Xlint:all,-path -Werror -d "$out/classes" -cp "$cassandra_jar:$cp_libs$sdk" \
  $(find "$here/src/main/java" -name '*.java')
"$jar" --create --file "$out/keytend-kmip-cassandra-tls.jar" -C "$out/classes" .

# Standalone tests, without a node: the factory, material and validator against the in-memory
# KMIP server (directly, and behind a mutual-TLS socket), with real JSSE handshakes. JUnit, AssertJ
# and Bouncy Castle (test certificates) come from Cassandra's test libraries.
test_lib="$cassandra/build/test/lib/jars"
[ -d "$cassandra/build/test/classes" ] || { echo "no $cassandra/build/test/classes: run ant build-test" >&2; exit 1; }
test_jars=""
for pattern in 'junit-4*.jar' 'hamcrest-2*.jar' 'assertj-core-*.jar' 'bcprov-jdk18on-*.jar' 'bcpkix-jdk18on-*.jar' \
               'bcutil-jdk18on-*.jar'; do
  found=$(find "$test_lib" -name "$pattern" | head -1)
  [ -n "$found" ] || { echo "no $pattern in $test_lib: run ant build-test" >&2; exit 1; }
  test_jars="$test_jars:$found"
done
test_cp="$out/classes:$cassandra_jar:$cp_libs$sdk:$testing$test_jars"
"$javac" --release 17 -Xlint:all,-path,-processing -Werror -d "$out/test-classes" -cp "$test_cp" \
  $(find "$here/src/test/java" "$here/cassandra-tests/unit" -name '*.java')
# The Cassandra-side dtest is compiled (against the checkout's test classes), not run here: it
# needs a Cassandra test run (see README.md). -unchecked: TestBaseImpl's own builder() warns.
mkdir -p "$out/dtest-classes"
"$javac" --release 17 -Xlint:all,-path,-processing,-unchecked -Werror -proc:none -d "$out/dtest-classes" \
  -cp "$out/test-classes:$test_cp:$cassandra/build/test/classes:$(find "$test_lib" -name '*.jar' | sort | tr '\n' ':')" \
  $(find "$here/cassandra-tests/distributed" -name '*.java')

cat > "$out/logback-test.xml" <<'XML'
<configuration><appender name="E" class="ch.qos.logback.core.ConsoleAppender"><target>System.err</target>
<encoder><pattern>%d{HH:mm:ss.SSS} %level %logger{0} %msg%n</pattern></encoder></appender>
<root level="INFO"><appender-ref ref="E"/></root></configuration>
XML
"$java" -ea -Dlogback.configurationFile="$out/logback-test.xml" -Djava.io.tmpdir="$out" \
  -Dcassandra.disable_tcactive_openssl=true -cp "$out/test-classes:$test_cp" \
  org.junit.runner.JUnitCore dev.keytend.kmip.cassandra.tls.KmipSslContextFactoryTest \
  dev.keytend.kmip.cassandra.tls.KmipTlsSocketTest

if [ "$install" = "--install" ]; then
  # lib/ is a node's classpath (bin/cassandra); build/lib/jars is ant's (tests, in-JVM dtests).
  # Neither JAR is a declared dependency of the trunk build, so both places get a copy.
  for dir in "$cassandra/lib" "$cassandra/build/lib/jars"; do
    rm -f "$dir"/keytend-kmip-[0-9]*.jar "$dir"/keytend-kmip-cassandra-tls.jar
    cp "$sdk" "$out/keytend-kmip-cassandra-tls.jar" "$dir/"
  done
  # The in-memory server, which the Cassandra-side tests use, only on ant's test class path
  # (build/test/lib/jars), never in lib/
  rm -f "$cassandra"/build/test/lib/jars/keytend-kmip-testing-*.jar
  cp "$testing" "$cassandra/build/test/lib/jars/"
  cp -r "$here/cassandra-tests/unit/." "$cassandra/test/unit/"
  cp -r "$here/cassandra-tests/distributed/." "$cassandra/test/distributed/"
  echo "installed into $cassandra (lib, build/lib/jars, build/test/lib/jars, test/unit, test/distributed)"
fi
