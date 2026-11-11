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

# Releasing keytend-kmip

This is the maintainer's runbook. A release is a GitHub release holding two
reproducible ZIPs, the binary distribution and its source, and beside them the
in-memory test server's JAR. A release X.Y.Z is also deployed to Maven Central
(step 3). A pre-release X.Y.Z-rc.N never is.

A release is built, tested, reported, then packaged. The release checks build
the distribution, run every test against it, and write the results to a reports
directory. The packaging puts those reports in the binary ZIP's `validation/`
([Where the results are](validation.md#where-the-results-are)). The docs hold no
results.

The maintainer prepares the version (step 1) and pushes its tag. The release
workflow then runs steps 1 to 3 on GitHub Actions
([The release workflow](#the-release-workflow)). Every step can also run
locally, with JDK 17, as this page describes it. The signing policy is in [SECURITY.md](../SECURITY.md#verifying-release-artifacts).
This page says how to follow it.

"The release checks" on this page means `tools/release-check.sh`, which runs
every check a release must pass ([the release checks](#the-release-checks)).

## What is published where

| Artifact | GitHub release (the binary ZIP's `lib/`, unless said) | Maven Central |
|---|---|---|
| `keytend-kmip-parent` POM | in the source ZIP | yes (the SDK's POM names it as parent) |
| `keytend-kmip` JAR, `-sources`, `-javadoc` (Caffeine bundled, relocated) | yes | yes |
| `keytend-kmip-<version>-cyclonedx.json` (the SDK's SBOM) | yes | yes (classifier `cyclonedx`) |
| `keytend-kmip-<version>-tests.jar` (the samples) | no | yes (the `samples` execution attaches it) |
| `keytend-kmip-micrometer` JAR, `-sources`, `-javadoc`, SBOM | yes | yes |
| `keytend-kmip-opentelemetry` JAR, `-sources`, `-javadoc`, SBOM | yes | yes |
| `keytend-kmip-testing` JAR, `-sources`, `-javadoc`, SBOM (the in-memory server, a test dependency) | JAR, `-sources` and SBOM as assets beside the ZIPs, **not** in them | yes |
| `keytend-kmip-integration` JAR, `-sources`, `-javadoc`, SBOM | yes | **no** |
| `keytend-kmip-cli` JAR (launcher in the binary ZIP's `bin/`), `-sources`, `-javadoc`, SBOM | yes | **no** |
| The CLI's and the lab's runtime libraries (slf4j-api, slf4j-simple, picocli, jackson-core) | yes | no (they are on Central already) |
| The release checks' reports | the binary ZIP's `validation/` | no |
| The source tree | the source ZIP, `keytend-kmip-<version>-src.zip` | no |

The binary ZIP holds no source tree: `lib/`, `bin/keytend-kmip-cli`, `validation/`,
`release.json`, `SHA256SUMS`, `LICENSE`, `NOTICE` and a short `README.md`. Its
`lib/` is flat. The CLI's and the lab's JAR manifests name their runtime JARs,
so `java -cp lib/keytend-kmip-cli-<version>.jar` (what `bin/keytend-kmip-cli`
runs) finds them there. `package-release.py` checks that every one is present.
The source ZIP holds the committed source tree, which builds the release with
`./mvnw`.

`keytend-kmip-testing` is test support. Applications add it in test scope, and
nothing needs it at run time. `package-release.py` refuses a release whose
`lib/` holds it, a JAR there with a class of `dev.keytend.kmip.testing`, or an
SBOM that lists it. Its JAR, `-sources` JAR and SBOM are separate assets of the
GitHub release, checked, listed in `SHA256SUMS` and signed like the ZIPs, so that
users can add it to their tests without building it or Maven Central. The
`central` profile signs and publishes it like the other libraries.

The SDK JAR bundles Caffeine, relocated to `dev.keytend.kmip.internal.shaded.caffeine`
(`sdk/pom.xml`, "The bundled Caffeine"). Its published POM is the dependency-reduced one, which
lists slf4j-api only. Its descriptor is `module-info.java` without the line that requires
Caffeine. Its `-sources` JAR holds the SDK's sources and Caffeine's, relocated. There the SDK's
sources import Caffeine under the relocated name, as its classes do. Its `-javadoc` JAR
documents the SDK's API only.

Two build details follow from this. The other modules take Caffeine in test scope, because
before `package` (`./mvnw test`, an IDE) their tests run the SDK's unshaded classes. The SDK's
own tests need the in-memory server, and Maven allows no dependency cycle, so `sdk/pom.xml`
copies the testing package's sources to `target/generated-test-sources`. The SDK JAR never
holds them.

The integration application is an interoperability laboratory with test-only
dependencies on Testcontainers and H2. It ships in the GitHub release for those
who run the lab. Nobody should depend on it as a library. `maven.deploy.skip`
and the `central` profile's `excludeArtifacts` keep it off Central. The command-line tool
is an application, not a library. It ships in the binary ZIP, and the same two settings keep it
off Central too.

## Done once

- [x] The GitHub organization `keytend` exists.
- [x] The Central namespace `dev.keytend` is verified, by DNS on
  `keytend.dev` (step 3, "Namespace").
- [ ] The repository's CI signing subkey is made, given to the workflows and
  published on both keyservers, and the Central Portal token is a repository
  secret ([The release workflow](#the-release-workflow), "Settings").

keytend-kmip lives in `keytend/keytend-kmip-java`. The POM's `url`, `scm` and
`issueManagement`, the README, SECURITY.md and the tools all name it.

## The release workflow

Two GitHub Actions workflows build and publish a release. They run in
`keytend/keytend-kmip-java` only.

`.github/workflows/release.yml` starts when a tag `vX.Y.Z` or
`vX.Y.Z-rc.N` is pushed. It runs three jobs:

1. **check.** The tag must name the POMs' version, a release version, and a
   commit on `main`.
2. **release-check.** It runs the full release checks on the tagged commit:
   `tools/release-check.sh --jdks "17 21 25" --integration --server` with the
   pinned keytend-kmip-server build
   ([The pinned keytend-kmip-server build](#the-pinned-keytend-kmip-server-build)).
   It downloads that build from the server's GitHub release and checks the
   release asset's and the archive's SHA-256 against
   `tools/kmip-server/pinned-image.properties`. The JDKs are Temurin 17, 21 and
   25. The job keeps the reports, `summary.txt` and `run.txt` as the artifact
   `release-check`, the first distribution build's JARs and SBOMs with the
   second build's unsigned Central bundle as `tested-build`, and the logs as
   `release-check-logs` when a check fails. This job holds no secret.
3. **release.** It builds nothing. It puts the `tested-build` files back into
   the checkout, packages them with the release checks' reports and signs them
   with the CI signing subkey, so what is signed is what was tested. It signs
   every file of the Central bundle too, whose JARs must be those same files,
   into the asset `keytend-kmip-X.Y.Z-central-bundle.zip`.
   `tools/package-release.py` refuses to unless the release checks passed on
   this commit. The signing keyring is removed before the next step. Then it
   fetches the release key from keyserver.ubuntu.com, as users do, and runs
   `tools/publish-release.sh X.Y.Z --publish --draft`, which verifies every
   signature and creates a **draft** release. An `-rc.N` is marked a
   pre-release.

A manual run of `release` (Actions, release, Run workflow) runs the first two
jobs on the branch's commit, and releases nothing. With `central_drop`, the
third job then signs as on a tag but makes no GitHub release: it uploads the
signed Central bundle to the Central Portal, waits for its validation and drops
it (`tools/central-upload.py --drop`), so nothing reaches Central. This tries a
bundle before a tag is pushed.

The maintainer reviews the draft: its notes, its assets and the
`release-check` artifact. Then the maintainer publishes it, or deletes it and
its tag. Publishing a release X.Y.Z starts `.github/workflows/publish-central.yml`
(step 3). Publishing a pre-release starts nothing.

`publish-central.yml` builds and signs nothing. It verifies the release's
`SHA256SUMS` signature against SECURITY.md's fingerprint, downloads the
release's `keytend-kmip-X.Y.Z-central-bundle.zip` and checks it against
`SHA256SUMS`. Then it uploads that bundle to the Central Portal as it is, and
publishes it once the Portal has validated it
(`tools/central-upload.py --publish`). So Central gets the JARs the release
checks tested, the GitHub release's own. A manual run takes a
published release's version and `drop` or `publish`. `drop` uploads the
bundle, waits for the Portal's validation and drops it, so nothing reaches
Central; it works for a pre-release too. `publish` takes a release X.Y.Z
only, and `tools/central-upload.py` refuses a bundle of any other version
before it uploads anything.

### Settings

Once, by the release key's holder, with the primary key at hand:

```sh
tools/ci-signing-subkey.sh
```

It asks once for the release key's passphrase and adds an Ed25519 signing
subkey to the release key, valid for two years. It removes the passphrase from
a copy of the subkey's secret in a temporary keyring, checks that the copy signs,
and stores it as the repository secret `KEYTEND_SIGNING_KEY`, with its
fingerprint as the variable `KEYTEND_SIGNING_SUBKEY`. The subkey in your own
keyring keeps its passphrase. If a run stops after adding the subkey, run it
again with `--subkey FINGERPRINT`, the fingerprint it printed, to use that
subkey rather than add another. Then publish the key on both keyservers, with the
commands it prints, before the first tag. The draft step and Central both
verify against the published key. The subkey belongs to this repository alone.
If the secret leaks, revoke that subkey ([the release key](#the-release-key)).

The Central Portal user token goes in two repository secrets. `gh secret set`
reads each value from the terminal, not from an argument:

```sh
gh secret set CENTRAL_TOKEN_USERNAME -R keytend/keytend-kmip-java
gh secret set CENTRAL_TOKEN_PASSWORD -R keytend/keytend-kmip-java
```

The workflows pin each action they use by commit, with its release in a comment.

## The first release

0.10.0 is the first release. Its pre-releases, tagged `v0.10.0-rc.N`, are signed GitHub
pre-releases, checked and packaged from a clone of the public repository, and none is deployed to
Maven Central. 0.10.0 has no earlier release to compare its API with, so while the tree builds
0.10.0 or one of its pre-releases, `sdk/pom.xml` pins no API baseline and the release checks
record `api-baseline` as SKIP ([API compatibility checks](#api-compatibility-checks)). Once
0.10.0 is published, it becomes the baseline
([Make the release the API baseline](#make-the-release-the-api-baseline)).

## Before 0.10.0

Steps 1 and 2 are the owner's settings. The rest follows this page. Tick each
one off in order:

1. [x] The release key is created and published on `keys.openpgp.org` and
   `keyserver.ubuntu.com` (step 3, "Signing key"). Its primary key
   fingerprint `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F` is under "Release key
   fingerprint" in SECURITY.md, where `tools/publish-release.sh` reads it.
2. [x] Private vulnerability reporting is enabled (Settings, Code security),
   and SECURITY.md's "Reporting a vulnerability" links its form,
   `https://github.com/keytend/keytend-kmip-java/security/advisories/new`.
3. [ ] For each pre-release `0.10.0-rc.N`, and then for 0.10.0: make the
   `Prepare version` commit (step 1) on `main`, and push its tag
   `v0.10.0-rc.N` (or `v0.10.0`). The release workflow runs the full release
   checks, with `--server`, and every check must pass. It then signs the release
   and creates its draft ([The release workflow](#the-release-workflow)).
4. [ ] Review the draft, publish it, and verify the release as a user would.
   A pre-release stays on GitHub. Publishing 0.10.0 deploys it to Maven Central
   (step 3). Once it is on Central, change "not on Maven Central" in README.md,
   docs/getting-started.md and SECURITY.md to the Central dependency.
5. [ ] Once 0.10.0 itself is published, make it the API baseline (the end of
   step 1). Set `api.baseline.name`, `api.baseline.version` (0.10.0) and its
   SHA-256 in `sdk/pom.xml`. Its stored-format fixtures,
   `formats/0.10.0/` and `renewal-formats/0.10.0/`, are already in the tree.
   Write `sdk/src/test/resources/api/0.10.0.txt` from the released JAR and add
   0.10.0 to `PublicSurfaceTest.RELEASES`. From then on the release checks
   fail an incompatible change within the same 0.x minor version, that is, in
   a patch release. A minor release, such as 0.11.0, may make one, and its
   notes must list it ([API compatibility checks](#api-compatibility-checks)).

## 1. Prepare the version

A version is X.Y.Z, or X.Y.Z-rc.N for a pre-release of the release X.Y.Z. In
this step, `VERSION` is the version you prepare and X.Y.Z its release. In the
file names and commands of the later steps, X.Y.Z stands for the whole version,
such as `0.10.0-rc.1`. Make one commit titled `Prepare version VERSION`:

- set the version of `pom.xml` and the `<parent>` version of every module
  (`sdk`, `testing`, `micrometer`, `opentelemetry`, `cli`, `integration-tests`).
  `./mvnw -B -ntp versions:set -DnewVersion=VERSION -DgenerateBackupPoms=false`
  changes all seven. They must all name VERSION before you run the release checks.
- change `# keytend-kmip X.Y.Z (unreleased)` in RELEASE.md to `# keytend-kmip X.Y.Z`.
  A pre-release's notes are its release's section, so the heading names X.Y.Z for it too;
- update the version where users copy it or follow its tag, in README.md, docs/index.md,
  docs/getting-started.md and docs/production.md, and in the build commands of the other docs
  and READMEs, which name the tree's JARs. A search for the version the POMs had lists each
  place, for example `git grep -nF 0.10.0-rc.1 -- '*.md'`;
- point the Javadoc's links to the docs at the tag:

  ```sh
  git grep -l 'keytend-kmip-java/blob/main/' -- '*.java' |
    xargs sed -i 's#keytend-kmip-java/blob/main/#keytend-kmip-java/blob/vVERSION/#'
  ```

Then run the release checks on that commit. The full run, which a tagged commit
must pass, and whose reports the release packages:

```sh
TZ=UTC tools/release-check.sh --jdks "17 21 25" --integration \
  --server <keytend-kmip-server's pinned Docker archive or image>
```

### The release checks

`tools/release-check.sh` refuses a tree with uncommitted changes. It never
builds in your checkout. Each part runs in a detached `git worktree` of HEAD
under the run directory, one Maven at a time. The run directory is
`/tmp/keytend-kmip-release-check.<timestamp>/`, or `--out DIR`, and keeps every
log. The script ends with a PASS/FAIL table (`summary.txt`) and exits non-zero
if anything failed.

It runs in this order: the tests and static checks, the two distribution builds,
the checks against keytend-kmip-server on the first build's JARs, the reports,
then the packaging of both builds with the reports, and last the checks of what
was packaged. The reports go to the run directory's `validation/`, which
becomes the binary ZIP's `validation/`
([Where the results are](validation.md#where-the-results-are)):

- `release-check.txt`: the table of every check before the packaging, with the
  commit, the arguments and the JDKs. The arguments name the run directory
  `<run directory>`, and the server's Docker archive and the API baseline by
  their file names, wherever they were downloaded. Its last line says whether
  they passed.
  `tools/publish-release.sh` refuses a binary ZIP whose last line does not
  start with `PASSED BEFORE PACKAGING`.
- With `--integration`: `workflows/` and `catalog/`, the summaries and HTML
  reports of the workflow suite and the catalog
  (`tools/summarize-validation.py`, `tools/summarize-catalog.py` and their
  renderers), from the verify runs' reports.
- With `--server`: `live-server.json`, one entry per check and KMIP version
  (`tools/release_reports.py`), and each live check's logs in a directory named
  after it (`server-probe/`, `interop/`, `bench-smoke/` and the others below).
- `osv-scanner.txt`, when OSV-Scanner is installed.

No local path goes into them: the run directory, the checkout and the home
directory are named (`<run directory>`, `<checkout>`, `~`), also in the
summaries and the gzipped catalog records. No test output goes into them
either: the Surefire and Failsafe reports stay in the run directory
(`surefire-*/`). The packaging and `tools/publish-release.sh` refuse reports
with a `TEST-*.xml`, a Surefire or Failsafe report, the home directory,
`/tmp/keytend-kmip-release-check` or another local path. A local path is one
under a home, temporary, mount, workspace or build directory (`/home`, `/tmp`,
`/var`, `/opt`, `/srv`, `/data`, `/scratch`, `/workspace`, `/nix` and the
like), a `file:` URL, or a Windows drive path, also JSON-escaped. The user name
counts in a path, as `~user` or `user@host`, or as the value of a user or owner
field, not as a word, so "root" in "Self-signed root validation" passes. Gzip
files are read uncompressed, JSON files also as their decoded strings, and text
that is not UTF-8 byte by byte. A gzip file that cannot be read, or a JSON file
that does not parse, is refused.

The packaging adds `recorded/` and merges `live-server.json` with the recorded
results, so each check keeps its latest result
([Recorded results](#recorded-results)).

The checks, in order:

- **`test-jdk17`.** `./mvnw -B -T 4 clean test -Dsdk.skipTests` on JDK 17. It
  runs the phases before `package`, as a contributor or an IDE runs the tests,
  against the SDK's classes rather than its JAR. The SDK's own tests are compiled but
  not run, since `verify-jdk17` runs them on the same JDK and classes (without
  17 in `--jdks` they run here). It fails unless every other module ran its
  tests. Reports go to `surefire-test-jdk17/`.
- **`verify-jdk17`, `-jdk21`, `-jdk25`.** `./mvnw -B -T 4 clean verify` on each
  JDK, with `-Pdistribution` (Javadoc, sources, SBOM) and the whole test matrix
  (`-Dkeytend.matrix=full`) on 17. Surefire reports go to `surefire-jdkNN/`.
  Besides the tests, verify fails on:
  - the enforcer rules: Maven and JDK versions, pinned plugin versions,
    dependency convergence, no dependency compiled for a JDK newer than 17, no
    class in two artifacts, and the SDK's runtime dependencies limited to the
    allowlist in [dependencies](dependencies.md);
  - any javac lint warning (`-Xlint:all` except `try` and `serial`), in main
    and test code;
  - any Error Prone warning, on JDK 21 (Error Prone does not run on 17; 25
    skips it when 21 is checked);
  - any doclint warning in the SDK's Javadoc (every group but `missing`);
  - any SpotBugs or find-sec-bugs finding in the SDK that
    `sdk/spotbugs-exclude.xml` does not exclude, on JDK 17 (21 and 25 skip it
    when 17 is checked);
  - a dependency license outside the allowed lists (license-maven-plugin);
  - unformatted Java or POMs (`./mvnw spotless:apply` formats them).
- **`format-fixtures-jdkNN`, `license-headers-jdkNN`.** `PersistedFormatsTest`
  and `LicenseHeadersTest`, read from those reports. Each must have run and
  passed.
- **`license_headers.py`.** `python3 tools/license_headers.py --check`. Without
  `--check` it adds missing headers.
- **`dependency-updates`.** The versions-maven-plugin reports of newer
  dependency, plugin and property versions, pre-releases ignored, in
  `logs/versions.log`. The check only writes the report, and passes once it is
  written. Read it before the release, and note anything left behind.
- **`api-baseline`, `api-compat`.** `tools/api-baseline.sh`, then
  `./mvnw -B -pl sdk -Papi-compat verify -DskipTests` (without SpotBugs, which
  `verify-jdk17` ran). The report is copied to `japicmp/`. While the tree builds
  the first release, 0.10.0, or one of its pre-releases, `sdk/pom.xml` pins no
  baseline: `api-baseline` is `SKIP`, the only `SKIP` the release checks
  allow, and `api-compat` does not run. With a baseline, an incompatible change
  fails only against one of the same 0.x minor version, or from 1.0 the same
  major ([API compatibility checks](#api-compatibility-checks)).
- **The live checks** (with `--server`).
  `tools/kmip-server/run-server.sh image` checks the archive or image against
  the pin. Then, on the first distribution build's JARs, with the server in
  podman, these run at once, each on servers of its own:
  - **`server-probe`.** `tools/server-probe/run.sh --versions "1.1 1.2 1.4 2.1
    3.0"` runs the scenarios in `all` with the server's defaults. `all` has the
    full `tls-issue-repeat` from KMIP 1.4, about three minutes a version.
  - **`server-probe-name-reuse-reserve`, `server-probe-lease-states-active`.**
    The same, with the server under `KMIP_DESTROYED_NAME_REUSE=reserve` and
    under `KMIP_LEASE_STATES=active`.
  - **`server-probe-max-lease-0`.** `--scenarios raw-leases,tls` at 1.4, 2.1
    and 3.0, under `KMIP_MAX_LEASE_SECONDS=0` (a Lease Time of 0, no limit).
  - **`interop`, `interop-minimal`.**
    `integration/keytend-kmip-server/run-interop.sh` runs the interop suite and
    its programs with the configured setup, then the suite with the minimal
    setup, on all seven versions.
  - **`bench-smoke`.** `tools/bench/run.sh --topologies live --versions "1.4
    2.1 3.0" --scale 0.05` runs every benchmark scenario against two servers.
    It checks the tool. Its figures are not results.
- **`live-run`.** The run's own result of every live check above, at every
  KMIP version it runs, must be there and `PASS`, on the pinned image, and the
  probe's `all` must have passed the full `tls-issue-repeat` at 1.4, 2.1 and
  3.0: every one of its checks, as many as the probe's source makes (each
  call, way of stopping and check), and none failed
  (`tools/release_reports.py complete`). A run without `--server` has none, so
  it fails here and cannot make a release. `tools/publish-release.sh` refuses
  the same.
- **`live-pin`.** Every live result the release would ship, the recorded ones
  with the run's over them, must be `PASS` and of the pinned server build, and
  only the check in [Recorded results](#recorded-results) may be recorded. It runs
  without `--server` too. The packaging and `tools/publish-release.sh` refuse
  the same.
- **`reports`** (with `--integration`). The workflow suite's and the catalog's
  summaries of the verify runs. They fail on a workflow failure, a client
  failure, or an exclusion without its rule. A release needs them: the
  compatibility tables rely on them.
- **`sbom-scan`.** OSV-Scanner on the first build's SBOMs
  ([scanning the SBOM](#scanning-the-sbom-for-known-vulnerabilities)). It fails
  on any finding. Without OSV-Scanner it does not run, and `release-check.txt`
  says so.
- **`distribution-a`, `-b`, `reproducible`, `reproducible-javadoc`.** Two
  unsigned distribution builds in separate git worktrees, the first under
  umask 0022, the second under umask 0077 and another time zone, whatever the
  caller's. The first is step 2's `verify`. The second is step 3's Central
  deploy as a dry run (`-DskipUpload=true`), unsigned and installing nothing.
  Each is packaged with the run's reports (`package-release.py --reports
  --in-release-check`, which packages before the run has finished, unsigned,
  and marks `release.json` `"packaged": "in release check"`).
  Every JAR, the SBOMs, both ZIPs and `SHA256SUMS` must have the same SHA-256
  (`repro-compare.txt`).
- **`central-bundle`.** Every JAR of the second build's Central bundle must be
  the one in its module's `target/`, and each one `SHA256SUMS` lists must have
  the SHA-256 it lists there. Every JAR of the published modules in
  `SHA256SUMS` must be in the bundle (`logs/central-bundle.log`). The check
  fails if the dry run did not say it skipped the upload.
- **`user-commands`.** Runs what the docs tell users to run, on the first
  build's release, each in an empty directory (`logs/user-commands.log`). It
  takes each block after a `<!-- release-check: NAME -->` line from the docs, so
  the docs and the release cannot drift apart. `gpg` is a stub there, since the
  check packages unsigned. `PackageReleaseSigningTest` and
  `PublishReleaseScriptTest` check the signatures. The commands are:
  - SECURITY.md's `verify` on a download of every asset, on the binary ZIP
    alone, and on the binary ZIP alone with one of its JARs listed under another
    hash, which must fail; its `verify-source` on the source ZIP alone, then
    `./mvnw package -DskipTests` in the unpacked source, without Git; its
    `verify-testing` on the in-memory server alone;
  - this page's `verify-all` (below);
  - `tools/publish-release.sh VERSION --unsigned` on a copy of the release, with
    RELEASE.md's heading as it will be without "(unreleased)". It checks the
    release and publishes nothing;
  - getting-started's `install-sdk` and `install-testing`, with `mvn` the
    tree's wrapper on an empty local Maven repository. It reads plugins from
    yours, without `dev.keytend`, which a build from source puts there. Then a
    project of the blocks marked `dependency`, with JUnit, runs the test marked
    `test`.

Options:

- JDKs come from `JDK17_HOME`, `JDK21_HOME` and `JDK25_HOME`, or else from the newest patch
  release of each version installed in SDKMAN, by version order (21.0.13 after 21.0.4).
- For a quick run, use `--jdks 17`, `--skip-verify`, `--skip-api` or
  `--skip-repro`. A quick run cannot make a release: the packaging and
  `tools/publish-release.sh` refuse its reports.
- `--integration` adds `-Pintegration` and the `reports` check. It needs
  Docker, or the rootless Podman socket when `DOCKER_HOST` is unset. A run
  without it cannot make a release.
- `--baseline` gives `tools/api-baseline.sh` a downloaded release ZIP or JAR.
  `--no-api-fail` reports incompatible changes without failing on them.
  Without it the script runs `gh release download`, which works only for a
  keytend-kmip release from `keytend/keytend-kmip-java`.
- `--allow-dirty` runs on a tree with uncommitted changes. They are not part
  of HEAD, so they are not checked.
- `--keep-trees` keeps the git worktrees for inspection.

Tag only a commit whose full run passed. Keep its run directory: step 2
packages its `validation/` into the binary ZIP.

### Recorded results

Some evidence comes from runs the release checks cannot make: the
[OASIS replay](validation.md#oasis-replay) and one live check against
keytend-kmip-server. Its last recorded result is committed in
`validation/recorded/`, and every binary ZIP carries it as
`validation/recorded/`:

- `index.json` lists every other file there, with the date it was recorded, the
  server it was taken on, and why the release checks do not produce it.
  `python3 tools/release_reports.py check` checks the list, and the packaging
  runs that check.
- `live-server.json` holds the latest result of the one live check the
  release checks do not run, the
  [Cassandra trunk](../integration/cassandra-trunk-tde/README.md) dtest, which
  needs a patched and built Apache Cassandra checkout: one entry per KMIP
  version. A new run replaces its entries; nothing is appended.

The packaging merges the run's `live-server.json` over the recorded one.

A release ships live results of the pinned server build only. The packaging
(with `--reports`), `tools/publish-release.sh` and the `live-pin` check refuse
a live result that is not `PASS`, one whose image is not the pin's, and a
recorded result of any other live check. The refusal names the command that
runs the check again. When the pin moves, record the dtest again on the new
image, read the entries, and commit `validation/recorded/live-server.json`:

```sh
tools/record-live.sh cassandra-dtest --server <the pinned Docker archive or image> \
  --cassandra ../cassandra-trunk
```

It builds the SDK in a git worktree of HEAD, runs the check on JDK 17, and
replaces the check's entries, `PASS` or `FAIL`. `cassandra-dtest` runs the
dtest twice, with the server leasing Deactivated keys (its default) and then
Active keys only. When `../cassandra-trunk` does not exist, it clones Apache
Cassandra there, applies the patches and builds it, as the integration's
README does by hand.

### The pinned keytend-kmip-server build

The probe's keytend-kmip-server build is pinned in
`tools/kmip-server/pinned-image.properties`. Every live tool runs the same build
through `tools/kmip-server/run-server.sh` ([README](../tools/kmip-server/README.md)).

- Build: keytend-kmip-server **0.10.0-rc.1**, release `v0.10.0-rc.1` of
  `keytend/keytend-kmip-server`, a pre-release whose assets are container
  images only.
- Source: the tag is commit `3f075e0d2ea4b561787d0bdf710e4d1ffa7d6c63`, and
  the image's `image.json` names the same commit as its `source_commit`.
- Release asset: `keytend-kmip-server-0.10.0-rc.1-signed-release.tar`, SHA-256
  `059f7ad9f0d2dcf6888a5bae839a5866d55c6d9bf0e03bd5bdad22ae05c221e2`.
- Archive: the linux/amd64 Docker archive
  `release/linux-amd64/keytend-kmip-server-0.10.0-rc.1.docker.tar` from the
  release's signed tar, SHA-256
  `79d4a6179ee6011dc54fbddb0a4fd0ca614f83f3c8766d706baef6e1c70a703b`.
- Image: ID `85df8bafcf54206615d73b993124428898c504a76a1bdec9eeed2f0af370d04a`,
  local tag `localhost/keytend-kmip-server:0.10.0-rc.1`.

Each value comes from the release's own files: the asset's SHA-256 from its
`.sha256` asset, and the archive's SHA-256, the image's tag and ID and the
source commit from `release/linux-amd64/image.json` in the signed tar.

Give `--server` the archive or the loaded image. For the archive, its SHA-256 is
checked, then it is loaded. For an image, its ID is checked. Every live check fails for any other image.
`--server-unpinned` runs another, for experiments, and records the check as
`UNPIN`, which is not a pass.

Before it was pinned, the archive was checked. The server repository's
`scripts/verify_release.sh 0.10.0-rc.1`, run from a checkout at the release tag
with `RELEASE_BASE=file://` the directory of the downloaded assets, passed and
loaded the image. Then, by hand, in that directory:

- The release's outer tar matched its `.sha256` asset.
- The inner `release/SHA256SUMS` was identical to the outer `SHA256SUMS`, and
  every entry passed `sha256sum -c`.
- `SHA256SUMS.asc` is a good OpenPGP signature by the keytend release key
  (primary fingerprint `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F`).
- The Sigstore bundle verified with cosign, as `verify_release.sh` checks it:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
cosign verify-blob --key cosign.pub --insecure-ignore-tlog=true \
  --bundle SHA256SUMS.sigstore.json SHA256SUMS
```

By default the server frees the names of destroyed objects
(`--destroyed-name-reuse allow`) and leases Deactivated objects
(`--lease-states active-deactivated`). The probe accepts both settings of each.
The release checks run the probe under the defaults and under each other
setting. `KMIP_*` variables reach the container, so
`KMIP_LEASE_STATES=active tools/server-probe/run.sh ...` runs the other setting.

To move the pin, change the file's lines and this section together.
`ServerPinTest` compares them. Then, on that commit, run the release checks
with `--server` and the new image, and record the Cassandra dtest again
([Recorded results](#recorded-results)). Until it is recorded on the new image,
the release cannot be packaged.

### Make the release the API baseline

A pre-release is never the baseline. After a release X.Y.Z from main, make it
the baseline in one commit:

- In `sdk/pom.xml`, set `api.baseline.name` (`keytend-kmip`),
  `api.baseline.version` (X.Y.Z) and `api.baseline.sha256` (the SHA-256 of the
  release's `lib/keytend-kmip-X.Y.Z.jar`).
- If no fixtures of X.Y.Z exist yet, add them. Compile `FormatFixtures` and
  `ChunkedFormatFixtures` against the released JAR. They write
  `sdk/src/test/resources/formats/X.Y.Z/`. Pin their hashes and add X.Y.Z to
  `WRITTEN` in `PersistedFormatsTest`. Never regenerate a pinned fixture.
- A release that changes the client certificate renewal's files adds its
  fixtures the same way: `RenewalFormatFixtures`, compiled against the
  released JAR, writes `sdk/src/test/resources/renewal-formats/X.Y.Z/`; pin
  their hashes and add X.Y.Z to `WRITTEN` in `RenewalFormatsTest`. The first
  set, 0.10.0's, was written by the code 0.10.0 ships, and `RenewalFormatsTest`
  checks that the tree still writes the same header.
- Add X.Y.Z to `PublicSurfaceTest.RELEASES` with its surface list, written from
  the released JAR by `PublicSurfaceTest`'s `main` (below).
- Set the POMs to the next version, which new elements' `@since` names.
- Point the Javadoc's links back at `main`, the reverse of step 1's `sed`.

The SDK needs slf4j-api at run time, and the binary ZIP's `lib/` has it. The
fixtures also need the in-memory server, which is not in `lib/`. Use the
release's `keytend-kmip-testing-X.Y.Z.jar` asset, downloaded beside the ZIP. The
commands below run in a checkout of the release's tag, or in its unpacked source
ZIP, with the binary ZIP unpacked there.

```sh
cp=keytend-kmip-X.Y.Z/lib/keytend-kmip-X.Y.Z.jar:$(ls keytend-kmip-X.Y.Z/lib/slf4j-api-*.jar)
cp=$cp:keytend-kmip-testing-X.Y.Z.jar
javac -cp "$cp" -d out \
  sdk/src/test/java/dev/keytend/kmip/kms/FormatFixtures.java \
  sdk/src/test/java/dev/keytend/kmip/kms/ChunkedFormatFixtures.java
java -cp "$cp:out" dev.keytend.kmip.kms.FormatFixtures \
  sdk/src/test/resources/formats/X.Y.Z
java -cp "$cp:out" dev.keytend.kmip.kms.ChunkedFormatFixtures \
  sdk/src/test/resources/formats/X.Y.Z
```

The surface list takes the SDK JAR and, for its classes to load, slf4j-api. It
lists the packages the JAR's module descriptor exports, without the relocated
Caffeine. After `./mvnw -pl sdk test-compile`:

```sh
java -cp sdk/target/test-classes:sdk/target/classes dev.keytend.kmip.PublicSurfaceTest \
  keytend-kmip-X.Y.Z/lib/keytend-kmip-X.Y.Z.jar $(ls keytend-kmip-X.Y.Z/lib/slf4j-api-*.jar) \
  >sdk/src/test/resources/api/X.Y.Z.txt
```

## 2. Build, package and sign the GitHub release

From a clean checkout of the tag, with the run directory of the tag's full
release checks (step 1):

```sh
release_epoch=$(git show -s --format=%ct HEAD)
TZ=UTC ./mvnw -B clean -Pdistribution,central deploy -DskipUpload=true \
  -Dmaven.install.skip=true -Dproject.build.outputTimestamp="$release_epoch"
python3 tools/package-release.py --check-signing   # the signing setup, on a scratch file
python3 tools/package-release.py --sign --reports <the run directory>/validation \
  --central-bundle target/central-publishing/central-bundle.zip
```

The `central` profile writes the Maven Central bundle of the same build,
`target/central-publishing/central-bundle.zip`, and `-DskipUpload=true` keeps
it from uploading anything. Without a key name (`-Dgpg.keyname`) it signs
nothing: `--central-bundle` signs every file of it but the checksums, refuses
it unless its JARs are the ones in each module's `target/`, and publishes it as
`keytend-kmip-X.Y.Z-central-bundle.zip` (step 3).

Build online. The CycloneDX plugin skips the SBOMs when Maven is offline (`-o`), and the
packaging script then stops and names the SBOM that is missing.

`--reports` takes the release checks' reports. Before it writes or signs
anything, the script refuses them unless they are of a full run of the release
checks that passed:

- `release-check.txt` names the commit it packages, and its last line starts
  with `PASSED BEFORE PACKAGING`.
- It has every row a release needs, each `PASS`: `test-jdk17`, `verify-jdk17`,
  `verify-jdk21`, `verify-jdk25`, `format-fixtures-jdkNN` and
  `license-headers-jdkNN` for each of them, `license_headers.py`,
  `api-baseline` (and then `api-compat`), `live-run`, `live-pin` and
  `reports`.
  `api-baseline` may be `SKIP` only for the first release, 0.10.0, and its
  pre-releases. No other row may be anything but `PASS`.
- Its arguments have `--integration`, and none of `--skip-verify`,
  `--skip-api`, `--skip-repro`, `--allow-dirty`, `--no-api-fail` and
  `--server-unpinned`.
- The reports hold the workflow suite's and the catalog's: `workflows/` and
  `catalog/` with their `summary.json` and pages, a run on JDK 17, 21 and 25
  in each summary, and every run file a summary names.
- `live-server.json`, merged over the recorded results, holds the run's own
  `PASS` of every live check on the pinned image, as `live-run` checks, and
  no result that is not `PASS`, recorded ones included.
- The run directory's `summary.txt`, beside `validation/`, names the same
  commit, ends with `RELEASE CHECK PASSED`, and has the checks of what was
  packaged, `distribution-a`, `distribution-b`, `central-bundle`,
  `reproducible`, `reproducible-javadoc` and `user-commands`, each `PASS`.
  `release-check.txt` is written before those checks run, so only
  `summary.txt` shows that they passed.
- The reports hold no test output and no local path
  ([The release checks](#the-release-checks)).

The release checks' own packaging passes `--in-release-check`. It packages
before those last checks have run, so it does not require the run's results,
signs nothing (a signing key refuses it), and is refused once the run's
`summary.txt` exists. Its `release.json` says `"packaged": "in release check"`,
where a release's says `"packaged": "release"`, so the two binary ZIPs differ
in `release.json` and `SHA256SUMS` only. `tools/publish-release.sh --publish`
refuses the release checks' packaging.

Without `--reports` the binary ZIP holds the recorded evidence alone, its
`release.json` says `"packaged": "without reports"`, and
`tools/publish-release.sh` refuses it.

The script writes two ZIPs to `target/releases/`:

- `keytend-kmip-X.Y.Z.zip`, the binary distribution, with no source tree. Its
  `lib/` holds each module's main, sources and Javadoc JARs and its SBOM (not
  the test-only `keytend-kmip-testing`'s, which go beside it) and the CLI's and
  the lab's runtime libraries. Beside `lib/` are the CLI's launcher
  (`bin/keytend-kmip-cli`), the reports (`validation/`), `release.json`,
  `SHA256SUMS` (every other file in the ZIP), `LICENSE`, `NOTICE` and a short
  `README.md`.
- `keytend-kmip-X.Y.Z-src.zip`, the source: the committed tree of the tag as
  `git archive` gives it, under `keytend-kmip-X.Y.Z-src/`.

With `--central-bundle`, it also writes the signed Central bundle,
`keytend-kmip-X.Y.Z-central-bundle.zip`.

Before writing them, the script checks:

- each module JAR's `META-INF/LICENSE` and `META-INF/NOTICE` are the repository's
  (the third-party JARs keep their own). The SDK's JARs also carry the bundled
  Caffeine's license, `META-INF/licenses/caffeine/LICENSE`, and the SDK JAR its
  `pom.properties`;
- the project's classes are Java 17 bytecode. The bundled Caffeine's (Java 11) and
  the SDK's descriptor (moditect writes it at Java 9's class version) are not newer,
  and nothing is under Caffeine's own package name;
- each `-sources` JAR has every committed source, the same bytes, except that the
  SDK's imports of Caffeine are relocated by shade's rule. The bundled sources keep
  their upstream headers;
- the SDK's `-javadoc` JAR has no page of a bundled package;
- the CLI's own copy of the SDK JAR is the one shipped, and every entry of the CLI
  JAR's manifest `Class-Path` is, by file name, a JAR in `lib/`;
- `lib/` holds no `keytend-kmip-testing` JAR, no JAR there has a class of
  `dev.keytend.kmip.testing`, and no SBOM lists it;
- the SDK's SBOM lists exactly its allowlisted runtime dependencies (slf4j-api and
  Caffeine), under their own coordinates, Caffeine at the bundled version with the
  property `keytend:shaded` naming its relocated package;
- `keytend-kmip-testing`'s JAR and `-sources` JAR pass the same checks as the
  modules', its JAR holds only `dev.keytend.kmip.testing` (and its descriptor), and
  its SBOM lists the SDK;
- `validation/recorded/` is the commit's, and its `index.json` lists every file
  there ([Recorded results](#recorded-results));
- the binary ZIP has nothing outside `lib/`, `bin/`, `validation/` and its
  top-level files.

Beside the ZIPs the script writes:

- `keytend-kmip-testing-X.Y.Z.jar`, `keytend-kmip-testing-X.Y.Z-sources.jar` and
  `keytend-kmip-testing-X.Y.Z-cyclonedx.json`, the files of `testing/target/`;
- a `.sha256` of each ZIP and of each of those three;
- `SHA256SUMS`: the binary ZIP's own `SHA256SUMS` with each path under
  `keytend-kmip-X.Y.Z/`, then that file's SHA-256, then the two ZIPs' and the
  three files'. So `sha256sum -c SHA256SUMS` beside the unpacked binary ZIP
  checks every one. The `SHA256SUMS` in the binary ZIP lists its contents only;
- the detached ASCII-armored signature (`.asc`) of each ZIP, of each of the
  three files and of `SHA256SUMS`.

The signatures are made by the release key's **signing subkey**
`AAE2AF4DD7F2427F52B800D494E026FE1BF6C09E` (Ed25519, signing only). Its primary
key fingerprint is `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F`, the one
SECURITY.md publishes. Step 3's `-Dgpg.keyname` names the same subkey. The
release workflow signs with the repository's CI signing subkey instead,
another subkey of the same release key (`--sign-key`, and `-Dgpg.keyname` in
step 3), so users verify against the same primary fingerprint.

How the script signs:

- The subkey signs unattended from a GnuPG home of its own. That home holds only
  the subkey's secret, and the primary is a stub there.
- The script runs `gpg --batch --pinentry-mode loopback --passphrase-file FILE
  --local-user AAE2…C09E! --armor --detach-sign`. The passphrase never appears in
  an argument or in the script.
- The home and the file are `KEYTEND_SIGNING_HOME` and
  `KEYTEND_SIGNING_PASSPHRASE_FILE`. The defaults are
  `~/.config/keytend-kmip-java/signing/gnupg` and `…/signing/passphrase`.
- The script refuses when either is missing, or when the file's mode is looser
  than 0600. `--sign-key KEY` (or `KEYTEND_GPG_KEY`) signs with another key of
  that home.
- Each signature is verified right after it is made. It must be a good
  signature by exactly that subkey, whose primary the script prints.
- The signatures stay outside the ZIPs, so the ZIPs are the same with or
  without them.
- Without `--sign` the script signs nothing, says the artifacts are UNSIGNED and
  removes stale `.asc` files. A key gpg cannot use fails the script, and leaves
  no signature.

### Reproducible builds

Building twice with the same `release_epoch` and the same reports gives the same
bytes for every JAR, the SBOMs, both ZIPs and every file beside them but the
signatures. That holds on
any machine with the same JDK 17 and Maven wrapper. `release-check.sh` builds
twice and compares, and the `sha256` the script prints can be compared with
another build's. The Javadoc JARs are included. The Javadoc is built without
class-use pages, which would make `index-all.html` depend on the file system's
directory order.

Maven runs in UTC whatever the machine's time zone, because `.mvn/jvm.config`
sets `-Duser.timezone=UTC`. A JAR entry's time is a local date and time, and the
shade and moditect steps of the SDK JAR write it in the JVM's zone. Without that
setting, the SDK JAR's bytes would follow the machine's zone (under
Pacific/Chatham, its entries were 13:45 off UTC's). The second build of the
release checks runs with `TZ=Pacific/Chatham` and another umask, so the check
still compares two environments.

The umask does not change the release either. The archivers copy each file's
permissions from disk into the JAR, so a build under umask 0077 makes entries
0600 and 0700 where one under 0022 makes 0644 and 0755. The `distribution`
profile therefore gives every entry of each JAR in a module's `target/` the
modes 0644 for a file and 0755 for a directory, in place, at
`pre-integration-test`. That phase comes after `package` wrote the last JAR,
and before `verify` signs them, `install` installs them and `deploy` stages
them for Central. It runs `python3 tools/package-release.py --canonical-modes`,
which changes only those modes in the JAR's central directory and recompresses
nothing. So the distribution build needs `python3`, and must run at least to
`verify`. `tools/package-release.py` refuses a JAR without those modes instead
of changing it, because a changed JAR would differ from the JAR deployed to
Central and from Maven's signature of it.

### Publish the GitHub release

Push the tag (`git push origin vX.Y.Z`). Then create the release with every asset
in one command. `tools/publish-release.sh` checks the packaged release and
prints that command. It publishes nothing unless `--publish` is given:

```sh
tools/publish-release.sh X.Y.Z              # checks, writes the notes, prints the command
tools/publish-release.sh X.Y.Z --publish    # the same, then runs it
```

It refuses unless all of these hold:

- `target/releases/` holds all seventeen assets. They are the binary ZIP, the
  source ZIP, `keytend-kmip-testing-X.Y.Z.jar`, `-sources.jar` and
  `-cyclonedx.json`, each with its `.sha256` and `.asc`, and `SHA256SUMS` with
  its `.asc`.
- Each `.sha256` is one line naming its file, with that file's hash.
- `SHA256SUMS` is the binary ZIP's own under `keytend-kmip-X.Y.Z/`, then that
  file's hash, then the hash of each of the five files, and nothing else.
- The binary ZIP has nothing outside `lib/`, `bin/`, `validation/` and its
  top-level files. Its `release.json` names the version, a commit, and
  `"prerelease": true` exactly when the version is X.Y.Z-rc.N. For a signed
  release it says `"packaged": "release"`.
- Its `validation/release-check.txt` is of that commit and says the release
  checks before packaging passed, with every row a release needs passing and
  none of the arguments that leave out a check, as the packaging requires.
- Its other reports hold no test output and no local path, and include the
  workflow suite's and the catalog's, as the packaging requires.
- Its `validation/live-server.json` holds the run's own `PASS` of every live
  check the release checks run, at every KMIP version, on the pinned image
  (`live-run`), and passing live results of the pinned build only
  (`live-pin`). A ZIP packaged from a run without `--server` is refused.
- Every entry of the source ZIP is under `keytend-kmip-X.Y.Z-src/`, and it holds
  `pom.xml`.
- Every signature is a good one by the release key. That is the fingerprint
  SECURITY.md publishes, or `--fingerprint FPR`.
- RELEASE.md has a `# keytend-kmip X.Y.Z` section, of the release, that is not
  marked "(unreleased)". That section, without development blocks, is the
  release notes. The script adds a list saying what each asset is.

With `--publish` it also refuses unless the tag `vX.Y.Z` names the commit in
the ZIP's `release.json`: on GitHub
(`gh api repos/keytend/keytend-kmip-java/commits/vX.Y.Z --jq .sha`) and, when
the clone you publish from has the tag, in the clone (`git rev-parse`).

The ZIP cannot show that the checks of what was packaged passed, because the
run's `summary.txt` is not in it. The signature stands for that:
`package-release.py` signs only after it has checked the whole run. So
`--publish` refuses `--unsigned`. `--unsigned` drops the `.asc` files and the
signature check, and only checks: the release checks run it on their own
packaging, whose `release.json` it notes. Only a version X.Y.Z-rc.N is
published as a pre-release (`--prerelease`). A release X.Y.Z, such as 0.10.0,
is a normal release, whatever its major version. A pre-release's notes start
with a line that names it.

A signature is accepted only with `GOODSIG` and `VALIDSIG`, with `VALIDSIG`'s
last field the primary fingerprint. Any of `EXPKEYSIG`, `REVKEYSIG`, `BADSIG`,
`ERRSIG`, `NO_PUBKEY` and `EXPSIG` refuses it. So a signature by an expired or
revoked subkey is refused. `KEYEXPIRED` and `KEYREVOKED` are not refusals,
because gpg prints them for any expired or revoked subkey of the key.

The command it prints for a signed release, with absolute paths:

```sh
gh release create vX.Y.Z --verify-tag --title "keytend-kmip X.Y.Z" \
  --notes-file target/releases/release-notes-X.Y.Z.md \
  target/releases/keytend-kmip-X.Y.Z.zip target/releases/keytend-kmip-X.Y.Z.zip.sha256 \
  target/releases/keytend-kmip-X.Y.Z-src.zip target/releases/keytend-kmip-X.Y.Z-src.zip.sha256 \
  target/releases/keytend-kmip-testing-X.Y.Z.jar \
  target/releases/keytend-kmip-testing-X.Y.Z.jar.sha256 \
  target/releases/keytend-kmip-testing-X.Y.Z-sources.jar \
  target/releases/keytend-kmip-testing-X.Y.Z-sources.jar.sha256 \
  target/releases/keytend-kmip-testing-X.Y.Z-cyclonedx.json \
  target/releases/keytend-kmip-testing-X.Y.Z-cyclonedx.json.sha256 \
  target/releases/keytend-kmip-X.Y.Z-central-bundle.zip \
  target/releases/keytend-kmip-X.Y.Z-central-bundle.zip.sha256 \
  target/releases/SHA256SUMS \
  target/releases/keytend-kmip-X.Y.Z.zip.asc target/releases/keytend-kmip-X.Y.Z-src.zip.asc \
  target/releases/keytend-kmip-testing-X.Y.Z.jar.asc \
  target/releases/keytend-kmip-testing-X.Y.Z-sources.jar.asc \
  target/releases/keytend-kmip-testing-X.Y.Z-cyclonedx.json.asc \
  target/releases/keytend-kmip-X.Y.Z-central-bundle.zip.asc target/releases/SHA256SUMS.asc
```

`--publish` refuses a release without its Central bundle. A check without
`--publish` takes it when it is there.

A pre-release's command also has `--prerelease`.

### Verifying a release

Before announcing it, download the release into an empty directory. Check it as
a user would, following [SECURITY.md](../SECURITY.md#verifying-release-artifacts):

<!-- release-check: verify-all -->
```sh
for f in keytend-kmip-X.Y.Z.zip keytend-kmip-X.Y.Z-src.zip keytend-kmip-testing-X.Y.Z.jar \
    keytend-kmip-testing-X.Y.Z-sources.jar keytend-kmip-testing-X.Y.Z-cyclonedx.json SHA256SUMS; do
  gpg --verify "$f.asc" "$f"
done
gpg --fingerprint 3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F   # the fingerprint SECURITY.md publishes
sha256sum -c *.sha256
unzip -q keytend-kmip-X.Y.Z.zip
sha256sum -c SHA256SUMS
(cd keytend-kmip-X.Y.Z && sha256sum -c SHA256SUMS)
```

Every signature must be "Good signature" from the primary key fingerprint in
SECURITY.md. Every line of `sha256sum -c` must say `OK`.

### Scanning the SBOM for known vulnerabilities

Each module the release ships has an SBOM in `lib/` that lists every library it
needs at run time:

- The SDK's lists slf4j-api, which applications resolve themselves, and
  Caffeine, which the SDK JAR bundles. Caffeine's entry has the property
  `keytend:shaded`, naming the package the SDK JAR has it under. Users cannot
  upgrade the bundled Caffeine, so a vulnerability in it needs an SDK release.
- The Micrometer module's lists Micrometer, and the OpenTelemetry module's the
  OpenTelemetry API.
- The CLI's and the lab's list the JARs `lib/` carries for them (picocli,
  jackson-core, slf4j-simple). `package-release.py` checks that each
  application's SBOM lists exactly those JARs.

The in-memory server's SBOM, beside the ZIP, lists the SDK and slf4j-api. Scan
all six before each release, and again whenever an advisory names a listed
library, with [OSV-Scanner](https://google.github.io/osv-scanner/):

```sh
# OSV-Scanner recognizes an SBOM by its file name (*.cdx.json).
for sbom in keytend-kmip-X.Y.Z/lib/*-cyclonedx.json keytend-kmip-testing-X.Y.Z-cyclonedx.json; do
  cp "$sbom" "$(basename "$sbom" -cyclonedx.json).cdx.json"
done
osv-scanner scan source $(printf -- '-L %s ' *.cdx.json)
```

A finding of High or Critical severity in a shipped library blocks the release
until a fixed version is in. The release checks run this scan (`sbom-scan`) when
OSV-Scanner is installed, and its output goes into the binary ZIP as
`validation/osv-scanner.txt`. Otherwise run it by hand on the first build's
SBOMs and save its output as `osv-scanner.txt` in the run directory's
`validation/` before step 2 packages it.

## 3. Deploy to Maven Central

A release X.Y.Z is deployed to Maven Central once its GitHub release is
published. A pre-release X.Y.Z-rc.N never is. `publish-central.yml` does it
([The release workflow](#the-release-workflow)), and the commands below do the
same by hand. Nothing is built in this step: the bundle is the release's
signed `keytend-kmip-X.Y.Z-central-bundle.zip` (step 2). The release checks
build it as a dry run (`central-bundle`), so it stays ready.

`tools/central-upload.py` uploads the bundle to the
[Central Portal](https://central.sonatype.com), waits until the Portal has
validated it, and publishes it (`--publish`) or drops it (`--drop`).
`--publish` refuses a bundle of any version but X.Y.Z before it uploads anything.

Without a key name (`-Dgpg.keyname`), the `no-signing-key` profile skips
signing, so `-Pcentral verify` works on any machine. Central refuses an
unsigned bundle at validation.

### One-time setup

1. **Namespace** (done). The groupId is `dev.keytend`, verified in the Portal
   with a TXT record on the `keytend.dev` domain. Nothing in the build depends
   on how it was verified.
2. **Portal token.** In the Portal, generate a user token and put it in
   `~/.m2/settings.xml`:

   ```xml
   <servers>
     <server>
       <id>central</id>
       <username>TOKEN_USERNAME</username>
       <password>TOKEN_PASSWORD</password>
     </server>
   </servers>
   ```
3. **Signing key** (done). The release key has primary key fingerprint
   `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F` and key ID `51E65DD49C6F987F`.
   It is Ed25519 with usage `[SC]`, created 2026-11-01 and expiring 2031-10-31.
   Its user ID is `keytend-kmip releases <releases@keytend.dev>`. Its holder
   keeps the primary off shared machines. Releases are signed by its signing
   subkey `AAE2AF4DD7F2427F52B800D494E026FE1BF6C09E` (Ed25519, `[S]`, expiring
   2028-11-03), from step 2's signing keyring. The public key, the subkey
   included, is on `keys.openpgp.org` and `keyserver.ubuntu.com`, which Central
   reads. Renewal and revocation are in [the release key](#the-release-key).

### Each release

Download the published release's bundle and `SHA256SUMS`, check them as
[Verifying a release](#verifying-a-release) does, then upload the bundle:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS   # Good signature, from SECURITY.md's fingerprint
sha256sum -c --ignore-missing SHA256SUMS
python3 tools/central-upload.py keytend-kmip-X.Y.Z-central-bundle.zip \
  --name "keytend-kmip X.Y.Z" --publish
```

`tools/central-upload.py` reads the Portal user token from
`CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD`, or else from the server
`central` of `~/.m2/settings.xml` ("One-time setup"). It uploads the bundle for
the user to publish, waits until the Portal has validated it, then publishes it
and waits until it is published. With `--drop` instead, it drops the validated
deployment, and nothing is published. Artifacts appear on Central some minutes
after publishing.

> [!WARNING]
> A version published on Central can never be changed or removed.

## The release key

SECURITY.md publishes the primary fingerprint, which users verify against. It
never changes while the key is in use.

The signing subkey expires two years after it is made. Before it
expires, renew it, or add a new signing subkey and retire the old one. Then
publish the key again on both keyservers. The primary key expires 2031-10-31.
Extend its expiry before then and publish the key again. Sign a release only
with a subkey that is valid when the release is published. A signature by an
expired subkey no longer verifies as good.

The CI signing subkey ([The release workflow](#the-release-workflow), "Settings")
also expires two years after it is made. Before it expires, run
`tools/ci-signing-subkey.sh` again. It adds a new subkey and replaces the
repository's secret and variable. Publish the key again, then let the old CI
subkey expire. A GitHub secret cannot be read back, so a CI subkey is never
used anywhere else.

If a subkey's secret is exposed, revoke that subkey with the primary key, and
publish the revocation on both keyservers. Add a new signing subkey and publish
the key again. Publish a security advisory naming the releases the exposed
subkey signed.

If the primary key is compromised, revoke it and publish the revocation. Create
a new release key, publish it, and put its fingerprint on SECURITY.md's
`**Release key fingerprint:**` line, where `tools/publish-release.sh` reads it.

## API compatibility checks

These checks enforce the promises in [compatibility](compatibility.md). The
release checks run them.

### The API baseline and japicmp

- Three properties in `sdk/pom.xml` pin the release used as the API baseline:
  `api.baseline.name`, `api.baseline.version` and `api.baseline.sha256`. That is
  the only place the baseline is pinned. `ApiBaselinePinTest` fails if another
  file pins it.
- `tools/api-baseline.sh` fetches the baseline's JAR, or takes it as a file,
  and checks its hash.
- `./mvnw -Papi-compat verify` then compares the SDK JAR with the baseline using
  [japicmp](https://siom79.github.io/japicmp/). The report goes to
  `sdk/target/japicmp/`. Review the changes `japicmp/api-compat.md` lists.
- The rule for the baseline: it is the latest release X.Y.Z, never a
  pre-release. The first release, 0.10.0, has none. While the tree builds
  0.10.0 or one of its pre-releases, `sdk/pom.xml` pins none,
  `tools/api-baseline.sh` says so and exits 3, and the release checks record
  `api-baseline` as `SKIP`, the only `SKIP` they allow. A tree of any other
  version without a pin is refused (exit 2), so no later release can skip the
  check. Once 0.10.0 is published, it is the first baseline.
- With a baseline, a binary or source incompatible change fails the build
  (`-Dapi.compat.fail=true`, the profile's default) when the baseline is of the
  same 0.x minor version as the tree, or from 1.0 the same major version
  (`tools/api-baseline.sh --fails` prints `fail`). A patch release must pass.
- A patch release X.Y.Z (Z above 0) is compared with a release of its own X.Y.
  Against an earlier one, such as 0.10.3 for 0.11.1, `--fails` refuses (exit 2)
  and says to make X.Y.0 the API baseline.
- The release checks fail closed: unless `--fails` exits 0 and prints exactly
  `fail` or `report`, `api-compat` is FAIL.
- Against a baseline of an earlier series (`--fails` prints `report`), such as
  0.10.x for 0.11.0, the release checks report the changes without failing on
  them, and `api-compat` fails unless RELEASE.md's section of the release has a
  `## Incompatible changes` heading that lists them
  ([While the major version is 0](compatibility.md#while-the-major-version-is-0)).
- `--no-api-fail` makes the report fail nothing. A run with it cannot make a
  release.
- The `testing` package is excluded, as the compatibility page leaves it out.
- Some changes the compatibility page allows are still reported by japicmp. Two
  examples are a protocol-tier element removed after its minor of deprecation,
  and an abstract method added to an interface only the SDK implements. Exclude
  each one in the `api-compat` profile, with a comment naming its RELEASE.md
  entry.

### Other API checks

- `PublicSurfaceTest` compares the public surface with the list of the last
  release in `PublicSurfaceTest.RELEASES` (`sdk/src/test/resources/api/X.Y.Z.txt`).
  The first list will be 0.10.0's. Until then there is none, and every element
  is new. Every element new since the last release needs `@since` with the
  release the tree builds (X.Y.Z, for a pre-release X.Y.Z-rc.N too). Every
  `@since` must name a release in `RELEASES` or that one. The test also fails
  while any published element is deprecated.
- `PublicJavadocTest` requires `@since` on every public type of `kms` and
  `testing`. It requires a Javadoc comment on every public and protected member
  of those packages, and `@deprecated` text on every deprecated one. It runs
  javadoc's doclint on them, which must report nothing.
- `ProtocolTierTest` checks the list of protocol-tier types that
  compatibility.md names as fixed points.
- The generated protocol tables (`Tag`, `Enums`, `Operation`, `Requests`)
  get `@since 0.10.0` from their generator, `tools/generate_registry.py`.
- `PersistedFormatsTest` opens a fixture of each stored format, with pinned
  hashes, through KMIP 1.4, 2.1 and the 3.0 draft. A release's fixtures
  (`sdk/src/test/resources/formats/X.Y.Z/`) are added by the time it becomes the
  API baseline, and never regenerated. The test fails while the API baseline
  release has none, and, while no baseline is pinned, while the release the
  tree builds has none. The first set is `formats/0.10.0/`.
