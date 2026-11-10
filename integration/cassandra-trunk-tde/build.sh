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

# Builds the Cassandra trunk commit log and hints key provider against a patched, built Cassandra
# trunk checkout and the SDK JAR, runs its standalone tests, and (with --install) puts both JARs on
# that checkout's classpaths and its Cassandra-side tests in its test tree.
#
#   integration/cassandra-trunk-tde/build.sh CASSANDRA_DIR SDK_JAR [--install]
#
# CASSANDRA_DIR is a git checkout of Apache Cassandra trunk with this integration's patches applied
# (git apply, each of patches/000*.patch in order) and `ant jar build-test` run on JDK 17 or later; the script checks
# both and stops otherwise. Nothing is written to it without --install.
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
[ -z "$install" ] || [ "$install" = "--install" ] || { echo "unknown option $install" >&2; exit 2; }
[ -f "$sdk" ] || { echo "no SDK JAR at $2" >&2; exit 2; }
javac=${JAVA_HOME:+$JAVA_HOME/bin/}javac
jar=${JAVA_HOME:+$JAVA_HOME/bin/}jar
java=${JAVA_HOME:+$JAVA_HOME/bin/}java

# The patches: applied to the checkout, and in the JAR it built (a patch applied after `ant jar`
# would compile here but fail at run time).
for p in "$here"/patches/000*.patch; do
  if ! git -C "$cassandra" apply --reverse --check "$p" 2>/dev/null; then
    if git -C "$cassandra" apply --check "$p" 2>/dev/null; then
      echo "$(basename "$p") is not applied to $cassandra: git -C $cassandra apply each of $here/patches/000*.patch," \
        "then ant jar build-test there" >&2
    else
      echo "$(basename "$p") neither applies to $cassandra nor is applied there (made against trunk 275a3a5)" >&2
    fi
    exit 1
  fi
done
cassandra_jar=$(find "$cassandra/build" -maxdepth 1 -name 'apache-cassandra-*.jar' \
  ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1)
[ -n "$cassandra_jar" ] || { echo "no Cassandra JAR in $cassandra/build: run ant jar" >&2; exit 1; }
"$jar" --list --file "$cassandra_jar" | grep -qx 'org/apache/cassandra/security/EncryptionKeyUnavailableException.class' \
  || { echo "$cassandra_jar was built without the patches: run ant jar build-test in $cassandra" >&2; exit 1; }
for source in src/java/org/apache/cassandra/security/CipherFactory.java src/java/org/apache/cassandra/hints/HintsDescriptor.java \
              src/java/org/apache/cassandra/metrics/CassandraMetricsRegistry.java; do
  [ "$cassandra/$source" -ot "$cassandra_jar" ] \
    || { echo "$cassandra/$source is newer than $cassandra_jar: run ant jar build-test in $cassandra" >&2; exit 1; }
done
cp_libs=$(find "$cassandra/build/lib/jars" -name '*.jar' ! -name 'keytend-kmip-*' | sort | tr '\n' ':')

out="$here/target"
rm -rf "$out"
mkdir -p "$out/classes" "$out/test-classes" "$out/dtest-classes"
# -path: the Class-Path entries of some third-party JARs' manifests name JARs Cassandra does not ship
"$javac" --release 17 -Xlint:all,-path -Werror -d "$out/classes" -cp "$cassandra_jar:$cp_libs$sdk" \
  $(find "$here/src/main/java" -name '*.java')
"$jar" --create --file "$out/keytend-kmip-cassandra-trunk-tde.jar" -C "$out/classes" .

# Standalone tests, without a node: the provider and the tool through Cassandra's own (patched)
# EncryptionContext and CipherFactory, against the in-memory KMIP server; and the hints
# changes of the patch. JUnit and AssertJ come from Cassandra's test libraries.
test_lib="$cassandra/build/test/lib/jars"
[ -d "$cassandra/build/test/classes" ] || { echo "no $cassandra/build/test/classes: run ant build-test" >&2; exit 1; }
test_jars=""
for pattern in 'junit-4*.jar' 'hamcrest-2*.jar' 'assertj-core-*.jar'; do
  found=$(find "$test_lib" -name "$pattern" | head -1)
  [ -n "$found" ] || { echo "no $pattern in $test_lib: run ant build-test" >&2; exit 1; }
  test_jars="$test_jars:$found"
done
test_cp="$out/classes:$cassandra_jar:$cp_libs$sdk:$testing$test_jars"
# -classfile: Guava's class files name error-prone annotations that Cassandra does not ship
"$javac" --release 17 -Xlint:all,-path,-processing,-classfile -Werror -d "$out/test-classes" -cp "$test_cp" \
  $(find "$here/src/test/java" "$here/cassandra-tests/unit" -name '*.java')
# The dtest is compiled (against the checkout's test classes), not run here: it needs a Cassandra
# test run and a real KMIP server (run-trial.sh). -unchecked: TestBaseImpl's own builder() warns.
"$javac" --release 17 -Xlint:all,-path,-processing,-unchecked -Werror -proc:none -d "$out/dtest-classes" \
  -cp "$out/test-classes:$test_cp:$cassandra/build/test/classes:$(find "$test_lib" -name '*.jar' | sort | tr '\n' ':')" \
  $(find "$here/cassandra-tests/distributed" -name '*.java')

cat > "$out/logback-test.xml" <<'XML'
<configuration><appender name="E" class="ch.qos.logback.core.ConsoleAppender"><target>System.err</target>
<encoder><pattern>%d{HH:mm:ss.SSS} %level %logger{0} %msg%n</pattern></encoder></appender>
<root level="INFO"><appender-ref ref="E"/></root></configuration>
XML
# One JVM per class (Cassandra initializes once per process: the provider test as a client, the
# hints test as a node). Run from target/: Cassandra's test configuration names its directories
# relative to the working directory, so the hints test's node directories are under target/build.
for test in dev.keytend.kmip.cassandra.tde.KmipKeyProviderTest org.apache.cassandra.hints.HintsKeyUnavailableTest; do
  (cd "$out" && "$java" -ea -Dlogback.configurationFile="$out/logback-test.xml" -Djava.io.tmpdir="$out" \
    -Dcassandra.config="file://$cassandra/test/conf/cassandra.yaml" -Dcassandra.storagedir="$out/build/test/cassandra" \
    -cp "$out/test-classes:$test_cp" org.junit.runner.JUnitCore "$test")
done

if [ "$install" = "--install" ]; then
  # lib/ is a node's classpath (bin/cassandra); build/lib/jars is ant's (tests, in-JVM dtests).
  # Neither JAR is a declared dependency of the trunk build, so both places get a copy. Only the SDK
  # JAR and this integration's are replaced; another integration's JAR stays.
  for dir in "$cassandra/lib" "$cassandra/build/lib/jars"; do
    rm -f "$dir"/keytend-kmip-[0-9]*.jar "$dir"/keytend-kmip-cassandra-trunk-tde.jar
    cp "$sdk" "$out/keytend-kmip-cassandra-trunk-tde.jar" "$dir/"
  done
  cp -r "$here/cassandra-tests/unit/." "$cassandra/test/unit/"
  cp -r "$here/cassandra-tests/distributed/." "$cassandra/test/distributed/"
  echo "installed into $cassandra (lib, build/lib/jars, test/unit, test/distributed)"
fi
