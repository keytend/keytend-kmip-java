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

# keytend-kmip-cli

> [!WARNING]
> **Experimental: not for production use.** Like the keytend-kmip SDK it is built on, the CLI
> is experimental in every release. Do not use it on keys that protect real data.

`keytend-kmip-cli` is a command-line tool for operators who manage keys on a KMIP server. It
lists keys, shows their attributes and rotation lineage, creates, activates and rotates keys,
expires, revokes and destroys them, retires and reconciles lineages, and stores and reads secrets.
It is built on the keytend-kmip application API, so it follows the same rules as applications
that use the SDK.

- [When to use it](#when-to-use-it)
- [Build and run](#build-and-run)
- [The configuration file](#the-configuration-file)
- [Global options](#global-options)
- [Commands](#commands)
- [What a key can do after expire, revoke and destroy](#what-a-key-can-do-after-expire-revoke-and-destroy)
- [Exit codes](#exit-codes)
- [Logging](#logging)
- [Safety notes](#safety-notes)
- [Output](#output)
- [JSON output](#json-output)
- [Limits](#limits)
- [Tested](#tested)
- [Dependencies and packaging](#dependencies-and-packaging)

## When to use it

Use it for day-to-day key operations from a shell: checking what a server holds, rotating a key,
expiring or retiring old keys, and handling a compromise. Applications should use the SDK itself.
For the keys of Cassandra commit log and hints encryption, use that integration's
[`KmipTool`](../integration/cassandra-trunk-tde/README.md), which reads `cassandra.yaml` and
scans the files before it retires a key.

## Build and run

You need JDK 17 or later. From the repository root, build the CLI and the SDK it needs:

```sh
./mvnw -pl cli -am package -DskipTests
```

This builds `cli/target/keytend-kmip-cli-VERSION.jar` and copies the JARs it needs at run time
to `cli/target/lib/` (see [Dependencies and packaging](#dependencies-and-packaging)). Run the
tool with the launcher script:

```sh
cli/bin/keytend-kmip-cli --help
```

or with `java -jar cli/target/keytend-kmip-cli-VERSION.jar --help`, which finds the other JARs
through the JAR's manifest. The release's binary ZIP has the launcher in `bin/`, beside `lib/`
with all the JARs. Set `JAVA_HOME` to choose the JDK, `JAVA_OPTS` to add JVM options, and
`KEYTEND_KMIP_CLI_JAR` to point at a CLI JAR elsewhere.

Every command line has this shape:

```sh
keytend-kmip-cli [--config FILE] [--group NAME] [--json] [--yes] COMMAND [ARGUMENTS] [OPTIONS]
```

Options may also follow the command. `--` ends the options. What follows is an argument, even when
it starts with `-`. `keytend-kmip-cli COMMAND --help` lists a command's options.

An option's value is given as the next argument or after `=`: `--name orders-kek`,
`--name=orders-kek`, `-g prod` or `-g=prod`. It may start with `-`, as in `--message --json`, but it
cannot be `--`. Each value is checked as the command line is read, before the configuration file. A
wrong value such as `--timeout soon` is a usage error (exit code 2), even for a command that does
not use it. The tool does not expand `@FILE` arguments.

## The configuration file

The tool connects to a **server group**: a named connection profile for one KMS. A group has an
ordered list of endpoints, a client identity, the trusted CAs, timeouts and KMIP version bounds.
Groups are defined in a configuration file, read from the first of:

1. `--config FILE`
2. the environment variable `KEYTEND_KMIP_CLI_CONFIG`
3. `~/.config/keytend-kmip/cli.properties`

The file uses the Java properties format, in UTF-8. Relative paths are resolved against the
file's directory. In the properties format a backslash is an escape, so write Windows paths with
`/` or `\\`.

```properties
# The group used when --group is not given.
default-group = prod

group.prod.description = Production KMS
# Replicas of one KMS, tried in this order: the next one is used when one is unreachable.
group.prod.endpoints = kms1.example.com:5696, kms2.example.com:5696
group.prod.identity.type = pkcs12
group.prod.identity.file = /etc/keytend/operator.p12
group.prod.identity.password-file = /etc/keytend/operator.p12.pass
group.prod.trust.type = pem
group.prod.trust.file = /etc/keytend/kms-ca.pem
group.prod.timeout = 30s
group.prod.connect-timeout = 10s
group.prod.min-version = 1.4
group.prod.max-version = 2.1

group.dr.endpoints = kms-dr.example.com:5696
group.dr.identity.type = pem
group.dr.identity.certificate = /etc/keytend/operator-chain.pem
group.dr.identity.key = /etc/keytend/operator-key.pem
group.dr.identity.password-env = DR_KEY_PASSWORD
group.dr.trust.type = jks
group.dr.trust.file = /etc/keytend/truststore.jks
group.dr.trust.password-prompt = true
group.dr.cipher-suites = TLS_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
```

Keys of a group, each prefixed with `group.NAME.` (a name is letters, digits, `-` and `_`):

| Key | Meaning |
|---|---|
| `description` | Free text, shown by `servers`. |
| `endpoints` | Required. `host:port` pairs, comma-separated, tried in order. List several only when they are replicas of one KMS that share the same keys. |
| `identity.type` | Required. `pkcs12` or `jks` (a key store with one private key and its chain), or `pem` (a certificate chain and a private key). |
| `identity.file` | The key store, for `pkcs12` and `jks`. |
| `identity.certificate`, `identity.key` | The PEM certificate chain and private key, for `pem`. |
| `identity.password-file` | A file holding the password of the key store, or of an encrypted PEM key. Give this or one of the next two. Required for `pkcs12` and `jks`. |
| `identity.password-env` | An environment variable holding that password. |
| `identity.password-prompt` | `true`: ask for that password at the console. |
| `trust.type` | Required. `pem` (a file of CA certificates), `pkcs12` or `jks` (a trust store), or `system` (the JDK's default CAs). |
| `trust.file` | The CA file or trust store. |
| `trust.password-file`, `trust.password-env`, `trust.password-prompt` | The trust store password, if it has one. |
| `timeout` | The call timeout: the deadline of each command's requests, including failover. Default 30s. |
| `connect-timeout` | The deadline of a TLS connection. Default 10s. |
| `min-version`, `max-version` | The KMIP versions the tool may negotiate, such as `1.4` and `2.1` (the defaults). `3.0` must be named to be used. |
| `cipher-suites` | TLS cipher suites, comma-separated. By default the JDK's, as the SDK chooses them. |

Durations are written `500ms`, `30s`, `15m`, `12h`, `30d` or in ISO-8601 (`PT30S`).

**Passwords are never written in the file.** A key such as `identity.password` is refused. A
password file holds the password and nothing else; one final line break is ignored. On a POSIX
file system the tool warns when other users can read it (`chmod 600`). Elsewhere it cannot check,
so keep the file in a directory only you can read. TLS protocol versions are the SDK's: TLS 1.3
and 1.2.

The default group is `default-group`, or the only group when there is one.

Every command goes through the SDK, which tries a group's endpoints in order. A read that fails on
one endpoint is retried on the next. A change goes to the first endpoint that can be reached, and is
never sent twice. When its reply is lost, the command says the outcome is unknown (exit code 3)
instead of repeating it.

## Global options

| Option | Meaning |
|---|---|
| `--config FILE`, `-c FILE` | The configuration file. |
| `--group NAME`, `-g NAME` | The server group. |
| `--json` | Print the result, or the error, as JSON on standard output. |
| `--yes`, `-y` | Confirm a change without asking. |
| `--timeout DURATION` | Override the group's call timeout for this command. |
| `--help`, `-h` | Help for the tool or a command. |
| `--version` | The tool's version, given on its own without a command; with `--json`, `{"version": "..."}`. |

## Commands

| Command | What it does | Changes keys |
|---|---|---|
| [`servers`](#servers) | List the configured server groups. | no |
| [`info`](#info) | Connect and show the server's versions and Query answers. | no |
| [`list`](#list) | List objects with their state, algorithm and dates. | no |
| [`show`](#show) | The attributes of one object, and its lineage. | no |
| [`lineage`](#lineage) | A key's rotation lineage. | no |
| [`create`](#create) | Create a symmetric key. | creates; `--if-absent` on a Pre-Active key needs confirmation |
| [`activate`](#activate) | Activate a Pre-Active object. | yes, needs confirmation |
| [`rotate`](#rotate) | Rotate the key a name leads to. | creates; `--grace` needs confirmation |
| [`expire`](#expire) | Stop a key from encrypting, now or at a date. | yes, needs confirmation |
| [`revoke`](#revoke) | Revoke a key, as compromised or not. | yes, needs confirmation |
| [`replace-compromised`](#replace-compromised) | Revoke as compromised and create a replacement. | yes, needs confirmation |
| [`destroy`](#destroy) | Destroy a key's material. | yes, needs confirmation |
| [`deactivate-predecessors`](#deactivate-predecessors) | Deactivate the older keys of a lineage. | yes, needs confirmation |
| [`retire-predecessors`](#retire-predecessors) | Destroy the older keys of a lineage. | yes, needs confirmation |
| [`reconcile`](#reconcile) | Join the newest keys of a name's lineage into one. | yes, needs confirmation |
| [`register-secret`](#register-secret) | Store a password or seed. | creates; `--replace` needs confirmation |
| [`get-secret`](#get-secret) | Read a secret's value. | no |
| [`renew-certificate`](#renew-certificate) | Renew the group's own client certificate. | the group's identity files; needs confirmation |

### `servers`

```sh
keytend-kmip-cli servers           # every group
keytend-kmip-cli servers prod      # one group
```

Shows each group's endpoints (in the order they are tried), identity, trust, timeouts, version
bounds and cipher suites. Passwords appear only as where they are read from, such as
`password from file /etc/keytend/operator.p12.pass`. A setting left to its default shows as
`default`, and is `null` in JSON. It sends nothing to any server. Alias: `groups`.

### `info`

```sh
keytend-kmip-cli --group prod info
```

Connects, then shows the negotiated KMIP version, the versions the server offers (Discover
Versions), and the server's answer to Query: vendor, server information, operations and object
types. A server that does not answer Discover Versions or Query is reported, and the command does
not fail. With `--json`, `serverVersionsError` or `queryError` holds the message, and the fields
that answer would fill are `null`. When no endpoint can be reached, it fails with exit code 8.
Alias: `ping`.

### `list`

```sh
keytend-kmip-cli list
keytend-kmip-cli list --name orders-kek
keytend-kmip-cli list --state active --kind symmetric-key --algorithm aes
keytend-kmip-cli list --object-group payments --custom x-purpose=orders
```

Lists the objects that match, with these columns: ID, name, kind, cipher (algorithm and length,
such as `AES-256`), state, Activation Date, Creation Date, Protect Stop Date, Deactivation Date
and object group. Dates that are not set show as `n/a`. All filters are optional and combine:

| Option | Matches |
|---|---|
| `--name NAME` | the name |
| `--state STATE` | `pre-active`, `active`, `deactivated`, `compromised`, `destroyed`, `destroyed-compromised` |
| `--kind KIND` | `symmetric-key`, `secret-data`, `private-key`, `public-key`, `certificate`, ... |
| `--algorithm ALG` | `aes`, `triple-des`, `hmac-sha256`, ... |
| `--object-group GROUP` | the KMIP Object Group (not on KMIP 3.0, which has none) |
| `--custom NAME=VALUE` | a custom attribute: `x-NAME` (client), `y-NAME` (server), `VENDOR:NAME`; a bare `NAME` means `x-NAME`. Repeatable. |

`list` is also a connectivity check. It fails with exit code 8 when the server cannot be reached.
Alias: `ls`.

### `show`

```sh
keytend-kmip-cli show 7f3a1c
keytend-kmip-cli show 7f3a1c --no-lineage
```

Shows these attributes of one object: kind, state, names, cipher (algorithm and length), usages,
object groups, custom attributes, the Creation, Activation, Process Start, Protect Stop,
Deactivation, Compromise Occurrence, Compromise and Destroy Dates, the Lease Time, links, and the
Extractable and Sensitive flags. A kind, state or algorithm this tool does not name is shown with
its protocol code, such as `OTHER(0x80000001)` for an algorithm. With `--json` the raw codes are
always there too: `rawObjectType`, `rawState`, `rawAlgorithm` and `rawUsageMask`. A Lease Time the
server sends malformed is shown as such, and `leaseTimeError` gives the reason.

For a key it also shows its rotation lineage, newest first. When the lineage cannot be read, the
attributes are still shown and the reason is given. With `--json`, `lineage` is then `null` and
`lineageError` holds the message.

### `lineage`

```sh
keytend-kmip-cli lineage orders-kek
keytend-kmip-cli lineage --id 7f3a1c
```

The keys of a rotation lineage, newest first, with their state, whether each is a newest key or
on a branch, the key each one replaced, the key `reconcile` joined it into, their names and dates.
A branch is a key that another caller's rotation of the same key left beside the main line. By
name it starts from the key the name leads to; `--id` starts from that key.

### `create`

```sh
keytend-kmip-cli create --name orders-kek
keytend-kmip-cli create --name orders-kek --if-absent
keytend-kmip-cli create --name archive-kek --bits 128 --object-group archive --custom purpose=archive
keytend-kmip-cli create --name staged-kek --pre-active
```

Creates a symmetric key, Active unless `--pre-active`, and prints its identifier on standard
output (a summary goes to standard error). `--algorithm` defaults to `aes`, `--bits` to 256 and
`--usage` to `encrypt,decrypt`.

`--if-absent` gets the key with the name, as the SDK's `findOrCreate` does:

- An Active key with the name is returned (`action` `found`).
- Otherwise a Pre-Active key with the name is activated (`activated`). Activation starts its
  cryptoperiod, so the command shows that plan first and needs `--yes` or a confirmation. Then the
  SDK activates the key shown, and only that key, in the call that returns it (`allowingPreActive`).
  A key another caller stages meanwhile is refused (exit 6) and stays Pre-Active.
- Otherwise a key is created (`created`).
- A name whose keys are only Deactivated or Compromised is refused (exit 6). Deactivated keys mean
  the name was retired on purpose, so create the new key under another name. Replace a Compromised
  key with `replace-compromised`.

With `--json`, `created` lists the keys this call is known to have created. It is empty when the key
was found or activated. It can name a second key when another caller created the name at the same
moment. The warning then says that key's state:

- Pre-Active: check it, and destroy it if it is yours.
- Active, when the other key was found only after this call activated its own: it may be in use, so
  move its data before retiring it.

`action` `recovered` means a reply was lost and reading back went past it. The warning says which
reply:

- The Create's: the key was then found by name, Active. This call or another caller made it. When
  the key found is Pre-Active, or cannot be read, the command exits with code 3 instead. Check the
  keys with `list --name NAME`, and activate one only if it is yours.
- The activation's: the key was then read back Active. This call or another caller activated it.
  When the key cannot be read back, the command exits with code 3 instead, and the hint names the
  key. Check it with `show ID`.

Without `--if-absent`, `create` refuses a name that an object not yet destroyed has already (exit
6). A second key with the name would be a duplicate. The SDK's name lookups keep choosing the first
key, other tools may choose either, and a server that enforces unique names refuses it.
`--allow-duplicate-name` makes the key anyway. To replace the key a name leads to, use `rotate`. The
check is made by the client (the SDK's `refusingExistingName`), not by the server, so two callers
creating the name at the same moment can both pass it. Only a server that enforces unique names
prevents that.

The summary on standard error needs one more read. When that read fails, the key still exists. The
command prints its identifier, warns, and exits with 0.

### `activate`

```sh
keytend-kmip-cli activate 7f3a1c
```

Activates a Pre-Active object, such as a key made with `create --pre-active`, or one a `create` left
Pre-Active when it stopped part-way. From then on it encrypts, and its cryptoperiod starts. KMIP has
no way back to Pre-Active. It shows its plan and needs `--yes` or a confirmation. An Active object
is reported, with nothing changed, also when another caller activated it while the confirmation
waited (`action` `none`, with a warning). Any other state is refused (exit 6).

### `rotate`

```sh
keytend-kmip-cli rotate orders-kek
keytend-kmip-cli rotate orders-kek --if-active-for 30d
keytend-kmip-cli rotate orders-kek --grace 7d
```

Rotates the Active key the name leads to. A new Active key, linked to the old one, takes the name.
Applications that seal through the SDK's `CurrentKey` move to it at their next check. The old key
stays Active. It still encrypts and decrypts, and nothing is revoked or destroyed.

- `--if-active-for DURATION` rotates the name's current key only when it has been Active that long.
  Otherwise it prints `Not due` and changes nothing. The current key is resolved when the command
  runs. When another caller rotated the key since, its successor is checked, and rotated if it is
  due too. A successor made moments ago is not due for a positive period, so the command usually
  makes no key then. `0s` is always due, so it always rotates. When another caller's rotation lands
  between the check and this command's Re-key, the command follows it and makes no key. With
  `--json`, `action` says which happened: `rotated`, `not-due` or `followed`, and `previous` is the
  key that was considered. Run it from one scheduled job. With `--grace` too, the plan names the
  current key, and the command acts on that key only. When another caller rotated it while the
  confirmation waited, it refuses (exit 6) and changes nothing.
- `--grace DURATION` also sets the old key's Deactivation Date to now plus the grace period,
  unless it has an earlier one, so the server deactivates it then. `--grace 0s` deactivates it at
  once. Because it changes the old key, `rotate --grace` prints its plan and needs `--yes` or a
  confirmation at the console. A scheduled job passes `--yes`. The result gives the old key's
  Deactivation Date as the server has it (`previousDeactivationDate`).
- `--shifted-dates` moves the old key's server-set dates forward for the new key (for a server
  policy that sets a cryptoperiod).

`action` `recovered` (with `rotated` `null`) means the Re-key's reply was lost, and reading back
found a replacement, which this call or another caller made.

When a rotation stops part-way (exit 7), do not repeat it. The hint names the new key and the
commands that finish the rotation, such as `activate`. A replacement found after a lost reply is
listed under `found`, not `created`, since this call may not have made it. A name that leads to
Secret Data is refused (exit 2). Give a secret a new value with `register-secret --replace`.

When the server refused a request about the old key after the rotation (its Deactivation Date, or
reading it), it may refuse `expire --at` too. The hint suggests `deactivate-predecessors` once the
grace period is over. When another step failed, such as reading the new key, the date was not asked
for yet. The hint says to check the old key's Deactivation Date with `show`, and set it with
`expire --at` if it is missing. See [Key lifecycle](../docs/operating-keys.md#rotate-on-a-schedule).

### `expire`

```sh
keytend-kmip-cli expire 7f3a1c                          # now
keytend-kmip-cli expire 7f3a1c --at 2026-12-01T00:00:00Z
keytend-kmip-cli expire 7f3a1c --at '2026-12-01 00:00:00'   # in the local time zone
```

Deactivates the key: it stops encrypting, and decrypts what it protected where the server's
policy allows ([after expire](#what-a-key-can-do-after-expire-revoke-and-destroy)). Use it for a key
switch: rotate first, so that the name leads to a new Active key, then expire the old one now or
at a date.

- **Without `--at`** the key is deactivated now. Up to KMIP 2.1 this is a Revoke with a reason
  that is not a compromise: `--reason`, default `unspecified`. On KMIP 3.0 it is the Deactivate
  operation, without a reason, because there a Revoke would make the key Compromised. The key's
  state becomes Deactivated.
- **With `--at`** the command sets the key's Deactivation Date. The key stays Active until then, and
  the server deactivates it at that date. The date must be in the future. The key is read again
  after the confirmation, and the command never postpones a Deactivation Date. When the key has an
  earlier one by then, that date is kept and the command changes nothing (`action` `none`). A date
  that passes while the confirmation waits is refused (exit 2). The same requests are sent on KMIP
  1.4, 2.1 and 3.0. Some servers do not let a client set this date. From KMIP 2.0 the command then
  fails with exit code 1. On KMIP 1.x such a server answers Permission Denied (exit 5), and the hint
  says so. Run `expire` without `--at` when the time comes.

KMIP has no compare-and-set, so another client can still change the date between the read and the
write. Change a key's lifecycle from one place at a time.

`--message TEXT` is recorded only without `--at`, and only up to KMIP 2.1:
`--reason superseded --message "key switch"`. The tool refuses `--message` where it would not be
recorded (exit 2), and `--reason` with `--at`.

`--at` takes ISO-8601: `2026-12-01T00:00:00Z`, `2026-12-01T01:00:00+01:00`, a local
`2026-12-01T00:00:00` or `2026-12-01 00:00:00`, or a date `2026-12-01` (its start). KMIP keeps
dates in whole seconds, so a fraction is rounded up.

The command does not set the Protect Stop Date. KMIP's Protect Stop Date also means "stop
encrypting, keep decrypting", and servers enforce it unevenly. The CLI's commands follow the
Deactivated state, not that date. The SDK's `LocalKeys` does check it, and hands out no key for
encryption past it. `list` and `show` display a Protect Stop Date that a server policy set.

Only an Active key can be expired now. A Pre-Active key encrypts nothing and KMIP cannot deactivate
it. Destroy it, or activate it first. `--at` is allowed on a Pre-Active key, and its plan says so.
The date takes effect once the key is Active. What a server does when the date passes while the key
is still Pre-Active is up to the server. A key that is Deactivated already is reported, with nothing
changed.

### `revoke`

```sh
keytend-kmip-cli revoke 7f3a1c --reason superseded --message "replaced by 9b20e4"
keytend-kmip-cli revoke 7f3a1c --reason key-compromise --compromised-at 2026-10-30T14:00:00Z
```

Revokes a key. `--reason` is required:

- `key-compromise` or `ca-compromise` makes the key **Compromised**, on every KMIP version. It
  needs `--compromised-at`, the time from which the key may have been exposed. This cannot be
  undone.
- `superseded`, `cessation-of-operation`, `affiliation-changed`, `privilege-withdrawn` or
  `unspecified` deactivate the key with the same request as `expire` without `--at` (on KMIP 3.0
  without recording the reason). Like `expire`, `revoke` refuses to deactivate a Pre-Active key
  (exit 6). A Compromised key cannot be deactivated either (exit 6). Destroy it once its data is
  re-encrypted.

`--message TEXT` is recorded with any reason. On KMIP 3.0 it is recorded only with a compromise
reason, and the tool refuses it with the others (exit 2).

For a compromised key, first check where it is in `lineage NAME`:

- If it is the newest key, the one the name leads to, use
  [`replace-compromised`](#replace-compromised), so that a new key takes the name.
- If it is an older key, revoke it with `revoke --reason key-compromise`. The name already leads to
  a newer key. If that key is compromised too, replace it as above.

Then re-encrypt the data under a clean key, and only then destroy the compromised key.

### `replace-compromised`

```sh
keytend-kmip-cli replace-compromised 7f3a1c --compromised-at 2026-10-30T14:00:00Z
keytend-kmip-cli replace-compromised 7f3a1c --compromised-at 2026-10-30T14:00:00Z --shifted-dates
```

Use it for the key a name leads to. It revokes the key as compromised and creates an Active
replacement that takes its names, linked to it where the server allows. It prints the
replacement's identifier. Applications that seal by name move to the replacement. Records under
the compromised key must be re-encrypted by the application
([A compromised key](../docs/operating-keys.md#a-compromised-key)).

The plan is the SDK's (`compromisePlan`): the key's state, its compromise date if it has one, its
replacements, each confirmed by both keys' links, and what the change does with them. The command
refuses before showing it:

- a key that a rotation has replaced already, unless it is Compromised (exit 6). Revoke that one
  with `--reason key-compromise` instead.
- a destroyed key (exit 6), and an object that is not a symmetric key (exit 2).
- a key with a replacement link the other object does not confirm (exit 6). The link proves nothing,
  so revoke the key with `revoke` and check the link.
- a key whose newest descendant is Deactivated or Destroyed (exit 6). That key cannot be the
  replacement, so find the key the name leads to with `list --name NAME`.
- a Compromised key without a replacement, or a Compromised descendant it would replace in turn,
  when a key an earlier attempt created for it is not linked (exit 6, `conflict`
  `unlinked-replacement`). A second one would leave that key unaccounted for. The hint names it.
  Destroy it if it is Pre-Active, still unlinked a few minutes after its creation date, and no other
  `replace-compromised` of the key is running, then repeat. Use it if it is Active.

The plan finds such a key by the client attribute it records, `x-keytend-replacement-of`. Some
servers cannot search by it: PyKMIP refuses the search, and others ignore the filter. Then the plan
says it could not check, the result warns, and `checkedForUnlinkedKeys` is `false`. On PyKMIP this
happens on every plan for a Compromised key without a replacement. Before you confirm, look in
`list --kind symmetric-key --state pre-active` for a key named `keytend-replacing-ID-…` or with no
name. Where the server refused that attempt's links, the key is Active instead, with the names the
compromised key had, and `lineage` does not show it. `show` either to see its
`x-keytend-replacement-of`. A busy server or a lost reply during the search exits with code 8. It
is not a refusal, so repeat the command.

A search that finds a key this client cannot read cannot tell either. Then the plan and the warning
name that key, and `unreadableCandidates` lists it. Have it checked with credentials that can read
it (`show ID`) before you confirm.

A key that is Compromised already is accepted, so that a call that stopped part-way can be
repeated. It keeps the first compromise's date and message, and the plan says that
`--compromised-at` and `--message` are not recorded. What happens next depends on its newest
descendant, and the plan says which:

| Newest descendant | What the command does | `action` |
|---|---|---|
| none: the key has no replacement | creates an Active replacement with its names | `completed` (`replaced` when it revoked the key) |
| Active or Pre-Active | finishes with it (activating that key only, moving the names) and creates nothing | `existing` |
| Compromised too | replaces that key as well: one new key takes both keys' names | `completed`, with `replacedInTurn` |

When callers replaced the key at the same time, or an earlier attempt's reply was lost, the key can
have several newest descendants, in a forked lineage. The command acts on one of them, which the SDK
chooses: an Active or Pre-Active one first, then one with names, then the earliest. The plan lists
each of the others as left as it is, a Pre-Active one included, and the result lists them under
`otherDescendants`, with a warning. Join the branches afterwards with [`reconcile`](#reconcile).

The change is bound to the plan (`replaceCompromisedResult`) and acts only on the keys it names.
The plan also says when it finishes a name move that an earlier attempt stopped part-way. Before its
first change the SDK makes the plan again and compares the two
([what it compares](../docs/kms-design.md#compromised-keys)). When they differ, the command refuses
and changes nothing (exit 6), so it never reports another caller's change as its own. Run it again
for a new plan. A refused step stops the command.

The result says whether this call revoked the key (`revoked`) and gives the compromise date in
effect (`compromiseOccurrenceDate`). A key that keeps an earlier compromise's date gets a warning.
Treat data sealed since the earlier of the two dates as possibly an attacker's. A key replaced in
turn keeps its own compromise date, which the text output prints. Re-encrypt its data too.

When a reply is lost (`action` `recovered`), the warning names only the steps no reply confirmed,
and `recoveredFrom` gives the step. A confirmed revocation stays `revoked`. When a step fails after
the revocation, the command exits with code 7 and lists the key under `deactivated`, since it stays
Compromised. Follow the message before you repeat the command for a new plan:

- When another caller's replacement appeared after the check, the repeat's plan shows it.
- When the Re-key's reply was lost, reading back cannot tell whether this command's Re-key or
  another caller's made the key it finds. The command stops without activating, linking or
  naming any of them, and the message names them. The repeat's plan shows them.
- Where the server refuses Re-key, the command creates the replacement under a temporary name,
  `keytend-replacing-` followed by the key's identifier and a random suffix. When the Create's reply
  is lost, it goes on (`recovered`) only when it can confirm the key it finds by that name
  ([how](../docs/kms-design.md#a-lost-create-or-register-reply)). Otherwise it stops, and the
  message says what the search found, or why it could not tell. When it found one object,
  `objectId` names it and the hint shows it with `show`. Check it before you repeat. A lost reply to
  the removal of the temporary name is read back and reported in `recoveredFrom`.

When the revocation's own reply is lost and the key cannot be read back, the command exits with
code 3.

`--shifted-dates` gives the replacement the key's cryptoperiod from now. `--copied-dates` copies
the key's dates, or makes a replacement without dates when its Deactivation Date has passed.
Without either, the SDK chooses from the key's dates.

### `destroy`

```sh
keytend-kmip-cli destroy 7f3a1c
```

Destroys the key's material. **This cannot be undone.** Everything still encrypted under the key
becomes unreadable, including backups, snapshots and replicas. Run it only after the key is
expired or revoked and its data has been re-encrypted under another key.

`destroy` refuses an Active key (exit 6): expire or revoke it first. At the console it asks you to
type the key's identifier instead of `yes`. A key that is destroyed already is reported, with
nothing changed. A compromised key ends Destroyed Compromised.

### `deactivate-predecessors`

```sh
keytend-kmip-cli deactivate-predecessors 9b20e4
keytend-kmip-cli deactivate-predecessors 9b20e4 --reason superseded --message "grace period over"
```

Deactivates the older Active keys of a lineage, from its newest key, and destroys nothing. It is the
step after a rotation's grace period, for a server that will not schedule the deactivation
([A server that will not schedule it](../docs/operating-keys.md#a-server-that-will-not-schedule-it)).
The identifier must be the lineage's newest key, and it must be Active. The plan lists the keys it
deactivates: the older keys that are Active now. Only those are deactivated. When another key of the
lineage is Active by then (activated while the confirmation waited), or the lineage changed, the
command refuses and deactivates nothing (exit 6). Run it again for a new plan. Keys that are
Pre-Active, Deactivated, Compromised or Destroyed are passed over. `--reason` defaults to
`superseded`. `--message` is refused on KMIP 3.0, where keys are deactivated without one. A call
that stops part-way (exit 7) can be repeated. It continues where it stopped.

A lineage of more than 64 rotations that are not destroyed is refused. Deactivate its older keys
one at a time with `expire KEY_ID`. Or, once nothing needs the oldest keys, retire them with
[`retire-predecessors`](#retire-predecessors) and `--keep-from`, and run this command again.

### `retire-predecessors`

```sh
keytend-kmip-cli retire-predecessors 9b20e4
keytend-kmip-cli retire-predecessors 9b20e4 --keep-from 5c11d0
```

Deactivates and destroys the older keys of a lineage, through the SDK's `retirePredecessors`. The
identifier must be the lineage's newest key (`lineage` shows it). `--keep-from` keeps that key and
every newer one and retires only the keys before it, including the keys `reconcile` joined into
them.

The plan is the SDK's. It lists exactly the keys that will be destroyed, in the order they are
destroyed, and says for each whether it is deactivated first. At the console you type their number
to confirm. Before its first change, the SDK reads the lineage again. When it changed, for example
because another caller rotated or reconciled meanwhile, the command refuses and destroys nothing
(exit 6). Run it again to see the new plan. Then it acts on the planned keys only. A change another
caller makes after that check is not detected, so make no other change to the lineage while it runs.
A lineage with several newest keys is refused before the plan. Join them first with `reconcile`. A
Compromised newest key is refused too. Retiring from it would destroy the lineage's last keys that
are not compromised, so replace it with `replace-compromised` and retire from the replacement.

A call that stops part-way exits with code 7 and lists the keys it destroyed and deactivated. Repeat
it to continue where it stopped.

The SDK reaches 64 rotations from a key. Retire a lineage of up to 128 rotations in two steps:
first with `--keep-from` a key at most 64 rotations from each end, then without it. For a longer
one, retire its oldest keys by hand first. Listing a lineage of more than 64 rotations from its
newest key is refused too. List it from an older key with `lineage --id OLDER_KEY_ID`.
To find one, `list` gives each key's ID and Creation Date, and in `show ID` the link
`replaced -> ...` names the key `ID` replaced. See
[Retiring part of a lineage](../docs/operating-keys.md#retiring-part-of-a-lineage).

### `reconcile`

```sh
keytend-kmip-cli reconcile orders-kek
```

Joins the newest keys of the lineage the name leads to into one, after callers rotated the same key
at the same moment. The plan is the SDK's (`reconcilePlan`): the key kept (the one `lineage` and the
SDK choose: Active first, holding a name, created first), the other newest keys joined into it (not
Compromised ones), the names moved to it, and the other Active keys deactivated last. Nothing is
destroyed, and everything sealed under the lineage still opens. A lineage with one newest key, which
alone is Active and has the names, is reported, with nothing changed. A kept key that is not Active
is refused before the plan (exit 6). When no object has the name, the plan finishes a name move that
stopped, if a key records one. Check that the key is yours.

Before its first change the SDK resolves the name and plans again. When the name now leads to
another lineage, or the reconcile would join, move or deactivate anything the plan does not list,
the command refuses and changes nothing (exit 6). Run it again for a new plan. Run it from the place
that rotates keys.

### `register-secret`

```sh
keytend-kmip-cli register-secret --name db-password --value-file /run/secrets/db-password
keytend-kmip-cli register-secret --name db-password --value-env NEW_DB_PASSWORD
keytend-kmip-cli register-secret --name db-password --value-prompt --replace 3d81aa
keytend-kmip-cli register-secret --name backup-seed --type seed --value-file seed.bin
```

Registers a password (`--type password`, the default) or a seed (`--type seed`) as KMIP Secret
Data, Active, and prints its identifier. The value comes from exactly one of `--value-file`,
`--value-env` or `--value-prompt`. It is never a command-line argument. A password typed at the
console is asked twice. A seed typed there is asked once and encoded as UTF-8. A password file's
final line break is dropped; a seed file is used byte for byte.

A name that an object not yet destroyed has already, a key's included, is refused (exit 6). A second
secret with the name leaves readers that look the name up on the first one.

To give the name a new value, use `--replace OLD_ID`. It moves the name from the old secret to the
new one and deactivates the old secret if it is Active. A Pre-Active, Deactivated or Compromised old
secret keeps its state, and a destroyed one is refused (exit 6)
([Replacing a secret](../docs/operating-keys.md#replacing-a-secret)). The confirmation shows which.
A Pre-Active secret with an Activation Date becomes Active by itself at that date, and is
deactivated if that happens before the name has moved. The confirmation shows the date. The
replacement then acts on that plan only. A state or an Activation Date that changed while the
confirmation waited is refused (exit 6) before anything is registered. The result says whether this
call deactivated the old secret (`replacedDeactivated`). An old secret another caller deactivated
first is reported as Deactivated, but not as this call's change. When the reply to this call's
deactivation was lost, the text says the call did not confirm who deactivated it, and a warning says
why.

The new secret is registered under a temporary name, `NAME.replacing-` and a random suffix. If the
Register's outcome cannot be confirmed
([how](../docs/kms-design.md#a-lost-create-or-register-reply)), the command exits with code 3 and
changes nothing more. The message gives the temporary name and what the search found, or why it
could not tell. When it found one object, `objectId` names it and the hint shows it with `show`.
`list --name NAME` does not show it, since it has the temporary name. Check it before you repeat.

Before the plan, the command refuses an `OLD_ID` that is not Secret Data, and a value source it
cannot read (both exit 2). `--allow-duplicate-name` registers another secret with the name anyway;
it does not go with `--replace`. As for `create`, the check is made by the client, not the server,
and only a server that enforces unique names prevents a race.

### `get-secret`

```sh
keytend-kmip-cli get-secret 3d81aa --out db-password.txt
keytend-kmip-cli get-secret 3d81aa --stdout | some-tool --password-stdin
```

Writes a secret's value to a new file, or to standard output with `--stdout`. It refuses a file
that exists, a symbolic link included, and `--stdout` does not go with `--json`. The file is
created and written through one open, so it cannot be swapped between the two. When the write
fails, the file is deleted. On a POSIX file system the file is created readable only by its owner
(mode `0600`). Elsewhere it gets the permissions of its directory, so write it to a directory only
you can read. With `--json`, `ownerOnly` says which happened. When standard output cannot be
written, for example a closed pipe, the command fails with exit code 1. An object that is not
Secret Data is refused (exit 2).

### `renew-certificate`

```sh
keytend-kmip-cli --group prod renew-certificate
keytend-kmip-cli --group prod renew-certificate --yes --json
```

Renews the client certificate that the group's identity holds, with KMIP Re-Provision, through
the SDK's `renewClientCertificate()`
([Renew the client certificate](../docs/production.md#renew-the-client-certificate)). The server
must offer Re-Provision (keytend-kmip-server with a provisioning CA), at KMIP 2.0 or later. The
command shows the plan and needs `--yes` or a confirmation, because it replaces the identity files
(`identity.certificate` and `identity.key`, or `identity.file`) and the server then refuses the
old certificate on new connections.

- The new private key is written beside the key file (`FILE.renewal`) before anything is sent, and
  an encrypted key or a key store keeps its password.
- After it, add the new fingerprint to the server's policy under the same name, then remove the
  old one. The command prints both.
- A group with several endpoints needs `--shared-store`: it states that the endpoints share one
  store.
- `--valid-for DURATION` asks for a validity period, such as `90d`, of at least ten minutes.
  keytend-kmip-server takes one. A server that does not take it, or
  keytend-kmip-server for a period that ends after its provisioning CA's notAfter, refuses the
  renewal before it issues anything, and the current certificate stays in use
  ([The validity period](../docs/production.md#the-validity-period)).
- Exit code 3 means the client may be locked out, also when the server issued a certificate the
  SDK refuses: the message says where the new key is and how to recover
  ([Lockout and recovery](../docs/production.md#lockout-and-recovery)).
- Exit code 3 also when the server issued the new certificate but the command could not write it
  to the files (a full disk, say). The server already refuses the old certificate, and the
  command is the only holder of the new one, so it prints the certificate chain in PEM on
  standard error before the message (with `--json`, in the error's `certificatePem`). Save it,
  fix the cause, and put it with the new key in the configured files
  ([What is on disk](../docs/production.md#what-is-on-disk)).
- An application or another run that renews the same files at the same time holds a lock file
  beside the key file (`FILE.renewal.lock`). The command then fails without sending anything, and
  says so: run it again once the other renewal is done. A later run
  finishes a renewal whose certificate was issued and saved but whose files were not all
  switched, before it connects.

With `--json` it returns `group`, `previousFingerprint`, `fingerprint`, `certificateId`, `subject`,
`notAfter` and `finishedEarlierAttempt`.

## What a key can do after expire, revoke and destroy

| After | State | Encrypts | Decrypts |
|---|---|---|---|
| `rotate` (old key) | Active | yes | yes |
| `expire`, `revoke` with a reason that is not a compromise, `deactivate-predecessors` | Deactivated | no | where the server's policy allows |
| `expire --at`, before the date | Active | yes | yes |
| `revoke` with a compromise reason, `replace-compromised` | Compromised | no | the SDK refuses unless the application asks for the compromised key explicitly; the server's policy decides |
| `destroy`, `retire-predecessors` | Destroyed (Destroyed Compromised) | no | no: the material is gone |

"Encrypts" includes wrapping, signing and computing MACs; "decrypts" includes unwrapping and
verifying.

- **Deactivated.** KMIP allows decryption with a Deactivated key only "under extraordinary
  circumstances and only when special permission is granted" (KMIP 1.4 §3.27). Servers differ. The
  in-memory server (`keytend-kmip-testing`) and keytend-kmip-server decrypt with it. A stricter
  server refuses unless your identity has that permission. Check yours with the application's own
  identity
  ([Deactivated keys and the server's policy](../docs/operating-keys.md#deactivated-keys-and-the-servers-policy)).
  No re-encryption is needed. Applications that seal through a `CurrentKey` move to the newest
  Active key of the lineage when a seal is refused.
- **Compromised.** A Compromised key cannot seal new data. An application can open or read it
  through `allowingCompromised()` to move its data. Treat data sealed after the compromise time as
  possibly an attacker's.
- **Destroyed.** Nothing the key protected can be decrypted again.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done, or nothing to do (for example, the key was already in the requested state). |
| 1 | Failed for another reason: the server, an unsupported feature, a local write, or an incomplete JAR in `lib/`. A change may have been made. |
| 2 | The command line or the configuration file is wrong, the SDK refused a setting or value before anything was sent, the object is of the wrong kind (`rotate` of Secret Data, `get-secret` of a key), or a runtime JAR is missing from `lib/` (checked at start). Nothing was changed. |
| 3 | **Outcome unknown**: a change may or may not have taken effect. |
| 4 | The object does not exist. |
| 5 | Permission denied: the client identity, or the object's access policy. |
| 6 | State conflict: the object's state, or an existing object, forbids the change. |
| 7 | Partly done: some steps of a multi-step change were made, then one failed. |
| 8 | The server could not be reached, or was busy. |
| 9 | Not confirmed: no `--yes`, and no confirmation at the console. Nothing was changed. |

Errors are printed to standard error as `error:` and, where it helps, `hint:` lines. With
`--json` they are printed to standard output instead (see [JSON output](#json-output)). A hint
that suggests a command gives it as a command line of this tool, with the same `--config` and
`--group`, and with values quoted for a POSIX shell where needed.

## Logging

Standard error carries the tool's own lines:

- `error:` and `hint:` when a command fails;
- `warning:` when a command succeeded although an endpoint of the group was unavailable, one line
  per endpoint, for example
  `warning: KMS endpoint kms1.example.com:5696 was unavailable; another endpoint served the command: connect: ...`.
  When the command fails, its `error:` line says why instead.

The SDK's own log lines ([Logging](../docs/production.md#logging)) go to standard error too,
through slf4j-simple, at WARN and above: for example, TLS files that did not reload. Its
`dev.keytend.kmip.kms.Endpoints` lines are off, since the tool reports endpoints itself. To trace
each call, attempt and retry, turn the `Calls` logger to DEBUG:

```sh
JAVA_OPTS=-Dorg.slf4j.simpleLogger.log.dev.keytend.kmip.kms.Calls=debug keytend-kmip-cli list
```

`-Dorg.slf4j.simpleLogger.defaultLogLevel=debug` shows every logger at DEBUG.

## Safety notes

**Changes to a key's state act on identifiers, never on names.** `activate`, `expire`, `revoke`,
`replace-compromised`, `destroy`, `deactivate-predecessors` and `retire-predecessors` take an
object identifier. A name moves to the new key at each rotation, so a command by name could hit a
different key than the one you checked. Find the identifier with `list --name NAME` or
`lineage NAME`, check it with `show ID`, then act on it. Names are not access control: anyone who
may create keys on the server can create one with your name.

**Changes to existing objects show their plan and ask first.** Those seven commands, `reconcile`,
`rotate --grace`, `create --if-absent` on a Pre-Active key and `register-secret --replace` print
what they will do to standard error, then need `--yes`, or a confirmation typed at the console:
`yes`, the identifier for `destroy`, and the number of keys for `retire-predecessors`. Without a
console and without `--yes`, they change nothing and exit with code 9.

`create`, `register-secret` without `--replace`, and `rotate` without `--grace` do not ask.
`rotate` takes a name and moves it to the new key, but leaves the old key Active.

**A confirmed change acts on what its plan named.** `retire-predecessors`,
`deactivate-predecessors`, `reconcile`, `replace-compromised`, `rotate --if-active-for --grace`,
`create --if-absent` and `register-secret --replace` pass the plan, or the key shown, to the SDK,
which checks it again before its first change. When the server would change an object the plan
did not name, or one that changed since, the command refuses and changes nothing (exit 6).

**One lifecycle writer per key.** KMIP has no compare-and-set or transactions. That check is made
once, before the first change, and another client can still act after it. Rotate, expire and
retire a key from one place at a time.

**Check a change whose outcome is unknown before you repeat it.** Changes are never re-sent. When
the reply to one is lost, the tool cannot know whether the server made the change, and exits with
code 3. Its hint says how to check: `show ID`, or for a key that has no identifier yet,
`list --name NAME`. A lost reply is read back where the SDK can tell, for example for `expire --at`,
which reports success when the date is set.

**A change that stops part-way lists what it did.** On exit 7 a multi-step change lists the objects
it created, deactivated and destroyed. Apart from them it lists, under `found`, the objects it went
on with but did not create: a replacement read back after a lost reply, which this call or another
caller made. Follow its hint instead of repeating the command. The hint says whether repeating
resumes (`retire-predecessors`, `deactivate-predecessors`, `reconcile`, `create --if-absent`) or
which command finishes the change (`activate` after `create`).

**Secrets stay off the command line.** Passwords for key stores and keys, and secret values,
come from files, environment variables or the console. `servers` shows only where each password
comes from.

## Output

When standard output cannot be written, the command fails with exit code 1. If it had made a
change, standard error says which, so that you check before you repeat it.

Names, identifiers, attribute values, server information and the SDK's messages can hold control
or bidi format characters. All text output (results, plans, errors, hints and warnings) prints them
as `\uXXXX`, so they cannot change your terminal or reorder what is shown. An identifier printed
alone, by `create` for example, is escaped too. A script that needs the exact value reads it from
`--json`. Its values are exact, and the JSON writer escapes the same characters. The console prompt
is escaped as well. To confirm `destroy` of such an identifier, type it escaped, as the prompt
shows it. `get-secret --stdout` writes the value unescaped.

## JSON output

With `--json`, every command prints one JSON object on standard output. Examples:

```sh
keytend-kmip-cli list --json --state active
keytend-kmip-cli create --name orders-kek --if-absent --json
keytend-kmip-cli expire 7f3a1c --yes --json
```

- Dates are ISO-8601 strings, and the Lease Time an ISO-8601 duration (`PT1H`).
- A field has one type. A value that is not set, a setting left to its default and a value the
  command could not read are `null`; the reason, if any, is in a separate field such as
  `lineageError`, `queryError` or `warning`.
- States, kinds and usages are the command-line tokens, such as `pre-active` and
  `symmetric-key`. The raw protocol codes are beside them (`rawState` and the like).
- `servers` returns `{"config", "defaultGroup", "groups": [...]}`, each group with its settings
  (a setting left to its default is `null`, and a password is where it comes from, never itself).
- `show` returns `id`, `kind`, `rawObjectType`, `state`, `rawState`, `names`, `algorithm`,
  `rawAlgorithm`, `length`, `usages`, `rawUsageMask`, the dates (`creationDate`, `activationDate`,
  `deactivationDate`, `processStartDate`, `protectStopDate`, `compromiseDate`,
  `compromiseOccurrenceDate`, `destroyDate`), `leaseTime` and `leaseTimeError`, `objectGroups`,
  `custom`, `links` (each `{"kind", "rawType", "target"}`), `extractable`, `sensitive`, and for a
  key `lineage` and `lineageError`.
- `list` returns `{"group", "count", "objects": [...]}`; each object has the fields of `show`
  without `lineage` and `lineageError`.
- `lineage` returns `{"keys": [...]}`, newest first, each with `id`, `state`, `newest`, `branch`,
  `names`, `replaced`, `replacedBy`, `joinedInto`, `activationDate` and `deactivationDate`.
- `activate`, `expire`, `revoke` and `destroy` return `id`, an `action` (`activated`,
  `deactivated`, `scheduled`, `revoked`, `destroyed`, or `none` when nothing changed), the `state`
  and `deactivationDate` read back after the change, and a `warning`. When that read fails, the
  change was still made: `state` is `null` and `warning` says why. `revoke` also returns `reason`.
- `create` returns `action` (`found`, `activated`, `created`, `recovered`), `id`, `created` (the
  keys this call is known to have created), `key` (the attributes, or `null` when they could not
  be read), `warning` and `recoveredFrom`.
- `rotate` returns `name`, `action` (`rotated`, `not-due`, `followed`, `recovered`), `rotated`
  (`null` when `recovered`: unknown), `previous`, `current`, `ifActiveFor` and `grace` (as given),
  `previousDeactivationDate`, `warning` and `recoveredFrom`.
- `replace-compromised` returns:
  - `compromised`, `replacement`, `warning` and `recoveredFrom`;
  - `action`: `replaced`, `completed`, `existing` or `recovered`;
  - `revoked`: whether this call's revocation took effect, its reply confirming it;
  - `compromiseOccurrenceDate`: the one in effect;
  - `replacedInTurn`: the Compromised descendants it replaced as well;
  - `created`: the key this call made, when its reply confirmed it;
  - `otherDescendants`: the newest descendants of a forked lineage that it left as they are;
  - `checkedForUnlinkedKeys`: `false` when the plan could not search for an earlier attempt's
    unlinked key;
  - `unreadableCandidates`: the keys that search found and could not read, otherwise empty.
- `recoveredFrom`, in each of these results, is `null` or the step whose reply was lost and that
  reading back went past. It has the shape of an error's `recoveredFrom`: `operation`, `objectId`
  and `message`. `objectId` is empty for a lost Create or Register. For a lost Activate or Revoke,
  or the removal of a replacement's temporary name, it is the key.
- `deactivate-predecessors` returns `newest` and `deactivated`. `retire-predecessors` returns
  `newest`, `keepFrom`, `planned` and `destroyed`. `reconcile` returns `name`, `action`
  (`reconciled` or `none`), `winner`, `joined`, `namesMoved` (from each key's identifier to the
  names it gives the winner) and `deactivated`, as planned.
- `register-secret` returns the fields below. Without `--replace`, all but `id`, `name` and
  `type` are `null`.
  - `id`, `name`, `type`, `replaced` and `recoveredFrom`;
  - `replacedDeactivated`: whether this call deactivated the old secret, its reply confirming it.
    It is `false` when another caller retired it first, or when the reply was lost;
  - `replacedState`: the old secret's state as the call left it;
  - `warning`: set when the reply to a change of the old secret was lost;
  - `deactivationRecoveredFrom`: the old secret's deactivation when its reply was lost, even after
    an earlier lost reply.
- `get-secret --out` returns `id`, `type`, `out`, `bytes` and `ownerOnly`.
- `info` returns `group`, `endpoints`, `version`, `serverVersions`, `serverVersionsError`,
  `vendor`, `serverInformation` (each field a list of values), `operations`, `objectTypes` and
  `queryError`.

An error is printed as:

```json
{
  "error": {
    "exitCode": 3,
    "status": "outcome-unknown",
    "message": "outcome unknown: ...",
    "hint": "the change may or may not have been made; check the object with: keytend-kmip-cli show 7f3a1c, then decide whether to repeat it",
    "category": "OUTCOME_UNKNOWN",
    "exception": "OutcomeUnknownException",
    "operation": "revoke",
    "objectId": "7f3a1c",
    "serverReason": null
  }
}
```

`category`, `exception`, `operation`, `objectId` and `serverReason` are there when the server or
the SDK raised the error; `category` is the SDK's `KmsException.Category`. A state conflict adds
`conflict` (`state`, `replaced`, `not-as-planned`, `name`, `lineage` or `unlinked-replacement`, the
SDK's `StateConflictException.Conflict`) and `observedState`. A partly done change (exit 7) adds:

- `created`, `deactivated` and `destroyed`: the identifiers of the objects it is known to have
  changed;
- `found`: the objects it went on with but did not create;
- `cause`: the step that failed, with its `exception`, `category`, `operation`, `objectId`,
  `serverReason` and `message`;
- `outcomeUnknown`: whether that step's outcome is unknown;
- `recoveredFrom`: in the same shape as `cause`, when an earlier step's reply was lost and `found`
  was read back after it; `null` otherwise.

When `outcomeUnknown` is `true`, the failed step may have taken effect too: check its `objectId`
with `show`. The lists are confirmed progress, not the server's whole state.

## Limits

- `create` makes symmetric keys only, and `rotate` and `replace-compromised` act only on them. There
  are no commands for key pairs or certificates. `list`, `show`, `activate`, `expire`, `revoke` and
  `destroy` work on any object.
- `register-secret` stores two kinds of Secret Data only: passwords and seeds.
- Scheduled expiry (`expire --at`) needs a server that lets a client set the Deactivation Date.
  Otherwise run `expire` without `--at` when the time comes.
- Each change acts on one identifier, or one lineage. Script several calls for more.
- There is no command to remove a name from a key.

## Tested

The tests in `cli/src/test` run every command against the in-memory server
(`keytend-kmip-testing`, a test dependency), at KMIP 2.1.
Listing, rotation, `create --if-absent`, `replace-compromised`, `register-secret --replace`,
scheduled expiry, revocation, the plan-bound changes and the escaped text output also run at KMIP
1.4 and 3.0. The tests cover confirmation, refusals, exit codes, the JSON output (parsed, with the
fields listed above), lost replies and the read-backs after them, partly done changes, changes made
by another caller while a confirmation waits, failover between two endpoints, and output that
cannot be written. The tool has not been run against a live KMIP server.

## Dependencies and packaging

The CLI is a separate module, `dev.keytend:keytend-kmip-cli`. It needs these JARs at run time:

- `keytend-kmip`, the SDK;
- `picocli`, which parses the command line and prints the help;
- `jackson-core`, which writes the JSON output;
- `slf4j-api`, through which the SDK logs;
- `slf4j-simple`, which prints the SDK's warnings and errors on standard error.

`./mvnw package` builds:

- `cli/target/keytend-kmip-cli-VERSION.jar`, whose manifest names the main class,
  `dev.keytend.kmip.cli.Main`, and lists each of those JARs twice on its class path: as
  `lib/NAME-VERSION.jar` and as `NAME-VERSION.jar`. The JVM skips the entries that do not exist;
- `cli/target/lib/`, with those five JARs.

The release's binary ZIP carries the CLI JAR and those five JARs in its `lib/`, and the launcher
in `bin/`. The launcher puts only the CLI JAR on the class path, and its manifest adds the five
JARs, so the other JARs in `lib/` are not used. The module is not published to Maven Central.
