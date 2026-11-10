/*
 * Copyright 2026 Jeremiah Jordan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.keytend.kmip.cli;

import dev.keytend.kmip.kms.AlreadyExistsException;
import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyRegistration;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.ObjectKind;
import dev.keytend.kmip.kms.OutcomeUnknownException;
import dev.keytend.kmip.kms.PartialCompletionException;
import dev.keytend.kmip.kms.ReplacementResult;
import dev.keytend.kmip.kms.SecretData;
import dev.keytend.kmip.kms.StateConflictException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** {@code register-secret} and {@code get-secret}. */
final class SecretCommands {
  private SecretCommands() {}

  static void register(Context c) {
    // A stray argument may be the secret itself: refuse it without repeating it.
    if (!c.args.positionals().isEmpty())
      throw CliException.usage(
          "register-secret takes no arguments; give the value with --value-file, --value-env or"
              + " --value-prompt");
    String name =
        c.args
            .value("--name")
            .orElseThrow(() -> CliException.usage("register-secret needs --name"));
    SecretData.Type type =
        c.args.get("--type", SecretData.Type.class).orElse(SecretData.Type.PASSWORD);
    if (type == SecretData.Type.OTHER) throw CliException.usage("--type must be password or seed");
    List<Secrets.Source> sources = new ArrayList<>();
    c.args.value("--value-file").ifPresent(f -> sources.add(Secrets.Source.file(Path.of(f))));
    c.args.value("--value-env").ifPresent(v -> sources.add(Secrets.Source.env(v)));
    if (c.args.flag("--value-prompt")) sources.add(Secrets.Source.prompt());
    if (sources.size() != 1)
      throw CliException.usage(
          "give exactly one of --value-file, --value-env or --value-prompt (never the value"
              + " itself)");
    Secrets.Source source = sources.get(0);
    Optional<String> replace = c.args.value("--replace");
    boolean allowDuplicate = c.args.flag("--allow-duplicate-name");
    if (allowDuplicate && replace.isPresent())
      throw CliException.usage(
          "--allow-duplicate-name does not go with --replace, which moves the name");

    KeyHandle old = null;
    KeyAttributes confirmed = null;
    if (replace.isPresent()) {
      // A source that cannot be read is refused before the plan is shown, not after it is
      // confirmed.
      c.secrets().check(source, type == SecretData.Type.PASSWORD ? "the password" : "the seed");
      c.targetId = replace.get();
      old = c.kms().keys().handle(replace.get());
      // The replacement acts on this plan only (KeyRegistration.replaceResult(old, attributes)):
      // a state or an Activation Date another caller changes while the confirmation waits is
      // refused, nothing registered.
      confirmed = confirmReplacement(c, name, old.attributes());
    }
    KeyRegistration registration = registration(c, type, source);
    Context.argument(() -> registration.named(name));
    // A second secret with a taken name leaves readers on the first one.
    if (old == null && !allowDuplicate) registration.refusingExistingName();
    String replaced = old == null ? null : old.id();
    c.targetId = null;
    c.targetName = name;
    c.hints(e -> registerHint(c, name, replaced, e));
    ReplacementResult replacing = old == null ? null : registration.replaceResult(old, confirmed);
    KeyHandle registered = replacing == null ? registration.register() : replacing.replacement();
    boolean deactivated = replacing != null && replacing.deactivatedPrevious();
    KeyState left = replacing == null ? null : replacing.previousState();
    // A change of the old secret whose reply was lost, read back past: it may be another caller's,
    // so the result does not claim it. The deactivation's own lost reply is reported even
    // after an earlier lost one. A lost step of the new secret is this call's own.
    boolean deactivationUnsure =
        replacing != null && replacing.deactivationRecoveredFrom().isPresent();
    String warning =
        deactivationUnsure
            ? "the reply to the deactivation of "
                + replaced
                + " was lost, and reading it back showed it "
                + Values.token(left)
                + (left == KeyState.DEACTIVATED
                    ? ": this call or another caller deactivated it"
                    : ": another caller took it out of use meanwhile, and this call's deactivation"
                        + " may not have taken effect")
                + ". Check the server's audit log if it matters which"
            : replacing != null
                    && replacing.recoveredFrom().flatMap(KmsException::objectId).stream()
                        .anyMatch(replaced::equals)
                ? "the reply to a change of "
                    + replaced
                    + " was lost, and reading it back showed the change ("
                    + replaced
                    + " is "
                    + Values.token(left)
                    + "): this call or another caller made it. Check the server's audit log if it"
                    + " matters which"
                : null;
    c.targetId = registered.id();
    c.done(
        "registered secret "
            + registered.id()
            + (replaced == null
                ? ""
                : deactivated ? " and deactivated " + replaced : ", replacing " + replaced));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", registered.id());
    result.put("name", name);
    result.put("type", Values.token(type));
    result.put("replaced", replaced);
    result.put("replacedDeactivated", replacing == null ? null : deactivated);
    result.put("replacedState", left == null ? null : Values.token(left));
    result.put("warning", warning);
    result.put(
        "recoveredFrom",
        replacing == null ? null : Cli.Failure.step(replacing.recoveredFrom().orElse(null)));
    result.put(
        "deactivationRecoveredFrom",
        replacing == null
            ? null
            : Cli.Failure.step(replacing.deactivationRecoveredFrom().orElse(null)));
    c.emit(
        result,
        () -> {
          c.out.println(registered.id());
          c.err.println(
              "Registered "
                  + Values.token(type)
                  + " "
                  + registered.id()
                  + " named "
                  + name
                  + (replaced == null
                      ? ""
                      : deactivated
                          ? "; " + replaced + " is deactivated"
                          : "; "
                              + replaced
                              + " no longer has the name and is "
                              + Values.token(left)
                              // Not by this call only when no reply of its own was lost.
                              + (left != KeyState.DEACTIVATED
                                  ? ""
                                  : deactivationUnsure
                                      ? " (this call did not confirm who deactivated it)"
                                      : ", not by this call")));
          if (warning != null) c.warn(warning);
        });
  }

  /**
   * Checks what the SDK refuses after the confirmation, before it, with this tool's hints, then
   * shows the plan of a replacement of {@code a} and asks for confirmation.
   *
   * @return {@code a}, the attributes the plan was made from
   */
  private static KeyAttributes confirmReplacement(Context c, String name, KeyAttributes a) {
    if (a.kind() != ObjectKind.SECRET_DATA)
      throw new CliException(
          ExitCode.USAGE,
          a.id() + " is " + Render.kind(a) + ", not a secret, so it is not replaced",
          "--replace takes the secret that has the name: see " + c.suggest("list", "--name", name));
    if (!a.names().contains(name))
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          a.id() + " does not have the name " + name + ", so it is not replaced",
          "find the object that has the name with: "
              + c.suggest("list", "--name", name)
              + "; it may have been replaced already");
    KeyState state = a.state();
    if (state != KeyState.ACTIVE
        && state != KeyState.PRE_ACTIVE
        && state != KeyState.DEACTIVATED
        && state != KeyState.COMPROMISED)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          a.id() + " is " + Render.state(a) + ", so it is not replaced",
          "a destroyed secret has no value to replace: register the new value under the name"
              + " without --replace");
    boolean deactivates = state == KeyState.ACTIVE;
    // A Pre-Active secret with an Activation Date becomes Active by itself at that date.
    boolean mayDeactivate = state == KeyState.PRE_ACTIVE && a.activationDate().isPresent();
    c.confirm(
        List.of(
            "register-secret " + name + ", replacing " + Render.summary(a),
            "  registers the new value, moves the name to it, and "
                + (deactivates
                    ? "deactivates " + a.id() + "."
                    : "leaves " + a.id() + " " + Render.state(a) + ".")
                + (mayDeactivate
                    ? " It activates at its Activation Date, "
                        + Render.date(a.activationDate())
                        + ": if it is Active once the name has moved, it is deactivated."
                    : ""),
            "  Readers that look the name up get the new value; "
                + a.id()
                + " can still be read by identifier."));
    return a;
  }

  /** The builder of the secret read from {@code source}; the value read is wiped. */
  private static KeyRegistration registration(
      Context c, SecretData.Type type, Secrets.Source source) {
    if (type == SecretData.Type.PASSWORD) {
      char[] password = read(c, source);
      try {
        return c.kms().keys().registerSecret(password);
      } finally {
        Arrays.fill(password, '\0');
      }
    }
    byte[] seed = c.secrets().bytes(source, "the seed");
    try {
      return c.kms().keys().registerSecret(type, seed);
    } finally {
      Arrays.fill(seed, (byte) 0);
    }
  }

  /** The hint for a failure of register-secret; {@code replaced} is OLD_ID, or null. */
  private static String registerHint(Context c, String name, String replaced, KmsException e) {
    if (e instanceof AlreadyExistsException)
      return "to give the name a new value, use --replace OLD_ID (see "
          + c.suggest("list", "--name", name)
          + "); --allow-duplicate-name registers another secret with the name anyway";
    // The name and the state were checked before the confirmation, and replace refuses before
    // registering anything: what it refuses changed while the confirmation waited.
    if (e instanceof StateConflictException s && replaced != null)
      return switch (s.conflict()) {
        case NAME ->
            replaced
                + " no longer has the name, so nothing was registered: another caller replaced"
                + " it; see "
                + c.suggest("list", "--name", name);
        case NOT_AS_PLANNED ->
            replaced
                + " changed while the confirmation waited (its state or Activation Date), so"
                + " nothing was registered; see the new plan by repeating the command";
        default ->
            replaced
                + " is "
                + s.observedState().map(Values::token).orElse("in another state")
                + " now, so nothing was registered: see "
                + c.suggest("show", replaced);
      };
    // A lost Register whose object could not be proved this call's: nothing changed. The
    // object in question has the temporary name, not NAME, so list --name NAME cannot show it.
    if (e instanceof OutcomeUnknownException && replaced != null)
      return replaced
          + " keeps the name "
          + Values.safe(name)
          + " and was not changed. "
          + e.objectId()
              .map(
                  other ->
                      "Check "
                          + other
                          + ", which has the temporary name, with: "
                          + c.suggest("show", other)
                          + " (with credentials that can read it, if these cannot)")
              .orElse(
                  "Look for an object with the temporary name the message gives ("
                      + Values.safe(name)
                      + ".replacing-…) with: "
                      + c.suggest("list", "--name", "TEMPORARY_NAME"))
          + ", before you repeat the command; destroy that object only if it holds no one's"
          + " value";
    if (e instanceof PartialCompletionException && replaced != null)
      return "the message says which object has the name now; check both with: "
          + c.suggest("list", "--name", name);
    if (e instanceof PartialCompletionException p && !p.created().isEmpty())
      return "activate the secret with: "
          + c.suggest("activate", p.created().get(0).id())
          + "; do not repeat register-secret, which would register another one";
    return null;
  }

  /** A password, asked twice at the console so that a typing mistake is caught. */
  private static char[] read(Context c, Secrets.Source source) {
    char[] first = c.secrets().chars(source, "the password");
    if (source.kind() != Secrets.Source.Kind.PROMPT) return first;
    char[] second = c.secrets().chars(source, "the password again");
    try {
      if (!Arrays.equals(first, second)) {
        Arrays.fill(first, '\0');
        throw CliException.usage("the two passwords differ; nothing was registered");
      }
      return first;
    } finally {
      Arrays.fill(second, '\0');
    }
  }

  static void get(Context c) {
    String id = c.args.single("a secret's identifier");
    c.targetId = id;
    Optional<String> out = c.args.value("--out");
    boolean stdout = c.args.flag("--stdout");
    if (out.isPresent() == stdout) throw CliException.usage("give one of --out FILE or --stdout");
    if (stdout && c.json)
      throw CliException.usage(
          "--stdout writes the raw value and cannot go with --json; use --out");
    Path file = out.map(Path::of).orElse(null);
    // Checked before the server is asked; the file is still created only if it does not exist.
    if (file != null && Files.exists(file, LinkOption.NOFOLLOW_LINKS))
      throw CliException.usage(file + " exists; get-secret writes only a new file");
    c.hints(
        e ->
            e instanceof KeyMismatchException
                ? id
                    + " is not Secret Data: get-secret reads secrets. See what it is with "
                    + c.suggest("show", id)
                : null);
    try (SecretData secret = c.kms().keys().handle(id).asSecretData()) {
      byte[] value = secret.bytes();
      boolean ownerOnly;
      try {
        if (file == null) {
          // Cli checks that standard output took it.
          c.out.write(value, 0, value.length);
          c.out.flush();
          return;
        }
        ownerOnly = write(file, value);
      } finally {
        Arrays.fill(value, (byte) 0);
      }
      Map<String, Object> result = new LinkedHashMap<>();
      result.put("id", id);
      result.put("type", Values.token(secret.type()));
      result.put("out", file.toString());
      result.put("bytes", value.length);
      result.put("ownerOnly", ownerOnly);
      String access =
          ownerOnly
              ? " (owner-only)."
              : " (not a POSIX file system: the file has its directory's permissions).";
      c.emit(
          result,
          () ->
              c.out.println("Wrote " + value.length + " bytes of " + id + " to " + file + access));
    }
  }

  /**
   * Writes {@code value} to the new file {@code file}, created and written through one open: it
   * must not exist (a symbolic link counts), and on a POSIX file system it is created mode 0600.
   * When the write fails, the file is deleted.
   *
   * @return true when the file was created owner-only (a POSIX file system); false when it has the
   *     permissions the file system gives a new file in its directory
   */
  private static boolean write(Path file, byte[] value) {
    boolean posix =
        file.toAbsolutePath().getFileSystem().supportedFileAttributeViews().contains("posix");
    Set<OpenOption> options = Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    FileAttribute<?>[] attributes =
        posix
            ? new FileAttribute<?>[] {
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            }
            : new FileAttribute<?>[0];
    SeekableByteChannel channel;
    try {
      channel = Files.newByteChannel(file, options, attributes);
    } catch (FileAlreadyExistsException e) {
      throw CliException.usage(file + " exists; get-secret writes only a new file");
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    try (SeekableByteChannel open = channel) {
      ByteBuffer buffer = ByteBuffer.wrap(value);
      while (buffer.hasRemaining()) open.write(buffer);
    } catch (IOException e) {
      try {
        Files.deleteIfExists(file);
      } catch (IOException notDeleted) {
        e.addSuppressed(notDeleted);
      }
      throw new UncheckedIOException(e);
    }
    return posix;
  }
}
