<!--
Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Licensing

keytend-kmip's own code and documentation are licensed under the
[Apache License 2.0](../LICENSE).
[NOTICE](../NOTICE) names the project and keeps the standards and third-party attributions.

## What the JARs contain

- Every module's JAR (the SDK, the in-memory test server, the two metrics modules, the CLI and the
  integration application) carries `META-INF/LICENSE` and `META-INF/NOTICE`, the repository's
  own. Apart from the SDK's bundled Caffeine, the JARs bundle no third-party code. The libraries
  they use are separate JARs under their own licenses ([dependencies](dependencies.md)).
- The SDK JAR bundles [Caffeine](https://github.com/ben-manes/caffeine) (Apache-2.0), relocated
  ([The bundled Caffeine](dependencies.md#the-bundled-caffeine)). NOTICE's "Bundled third-party
  code" names its version, copyright and origins. Its license is
  `META-INF/licenses/caffeine/LICENSE`, as Caffeine ships it, so it never replaces the SDK's own
  `META-INF/LICENSE`.
  `META-INF/maven/com.github.ben-manes.caffeine/caffeine/` holds its `pom.properties` and POM, so
  that scanners that read a JAR's contents find the bundled version.
- `./mvnw -Pdistribution install` also builds source and Javadoc JARs. The SDK's source JAR holds
  Caffeine's sources, relocated, and the same two license files as the SDK JAR. The notices are
  copied into the Javadoc JAR, next to the JDK doclet's own legal notices. The Javadoc documents
  the SDK's API only.
- The binary ZIP's `lib/` also holds the libraries the CLI and the lab run with (slf4j-api and
  the others `cli/target/lib/` lists). They are other projects' JARs, each with its own license
  files.

## Source headers

Each authored file starts with the Apache header for a copyright owner, from the license's
appendix. This follows the Apache Software Foundation's
[guidance for projects outside the ASF](https://www.apache.org/legal/apply-license.html#new).
The ASF contributor-agreement header does not apply, because the ASF does not own this project.

Headers use the comment syntax of each file type. This covers Java, Python, Go and shell
sources, Dockerfiles, build files, SVG and the documentation. Shebangs and XML declarations
stay on the first line. Generators write the header into generated Java and HTML.

Data files (JSON, TSV, CSV) and checksums carry no header, because a comment would break their
format. The distribution's LICENSE and NOTICE cover them.

To check the headers:

```sh
python3 tools/license_headers.py --check
```

Without `--check`, the tool adds the header to new files. `LicenseHeadersTest` applies the same
rules in every `./mvnw verify`. It also checks that each JAR's `META-INF/LICENSE` and
`META-INF/NOTICE` match the repository's, that the bundled Caffeine's license is the one Caffeine
ships, and that NOTICE names the Caffeine version the build bundles.

## Material under other licenses

- The OASIS test fixtures and the Maven wrapper keep their original notices. The
  interoperability catalog in `integration/catalog` and its tests are the Keytend project's own
  work, under Apache-2.0.
- The Krypton bootstrap keeps its upstream attribution and marks the changes made here.
- Each server used in the integration tests keeps its own license. Downloading or running one
  does not place it under Apache-2.0.
