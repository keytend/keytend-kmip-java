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

import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.kms.AlreadyExistsException;
import dev.keytend.kmip.kms.CipherSpec;
import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.InvalidRequestException;
import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsKeys;
import dev.keytend.kmip.kms.LinkKind;
import dev.keytend.kmip.kms.LocalUse;
import dev.keytend.kmip.kms.NotFoundException;
import dev.keytend.kmip.kms.PartialCompletionException;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.kms.Rewrapped;
import dev.keytend.kmip.kms.Rotation;
import dev.keytend.kmip.kms.StateConflictException;
import dev.keytend.kmip.kms.TlsIdentity;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import dev.keytend.kmip.kms.TlsIdentityHandle;
import dev.keytend.kmip.kms.TlsTrustFollower;
import dev.keytend.kmip.kms.UnsupportedException;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;

/**
 * Opt-in live probe of the kms layer's rotation, grace, deactivation, reconcile and retirement paths,
 * and of TLS identities (kms.tls())
 * against a real KMIP server (written for keytend-kmip-server). Not part of the build or the tests: run it
 * with {@code tools/server-probe/run.sh} (see the README next to this file), or by hand:
 *
 * <pre>
 * java -cp keytend-kmip.jar tools/server-probe/ServerProbe.java --endpoint 127.0.0.1:5696 \
 *     --version 3.0 --pki /path/to/pki [--scenarios all|grace,deactivate-predecessors,...]
 * </pre>
 *
 * Every observation is one line: {@code PASS}/{@code FAIL} against what the SDK documents (or the
 * KMIP rule named in the step), {@code INFO} for what is only recorded, {@code SKIP} for a scenario
 * that does not apply to the version or this SDK. Exit status 0 when no FAIL, 1 otherwise, 2 on a
 * probe error. Only the public API is used, plus {@code kms.protocol()} for the low-level steps.
 */
public final class ServerProbe {
  private static final byte[] PLAINTEXT = "server-probe record".getBytes(StandardCharsets.UTF_8);

  private static KmipVersion version;
  private static String v;
  private static Kms kms;
  private static KmsConfig.Endpoint endpointOf;
  private static Path pkiDir;
  private static String run;
  private static int graceSeconds = 3;
  private static int pass, fail, info, skip;
  /** Whether the run is {@code all}, not scenarios named one by one. */
  private static boolean all;

  interface Scenario {
    void run() throws Exception;
  }

  public static void main(String[] args) throws Exception {
    Map<String, String> a = parse(args);
    String endpoint = need(a, "endpoint");
    v = need(a, "version");
    version = KmipVersion.valueOf("V" + v.replace('.', '_'));
    Path pki = Path.of(need(a, "pki"));
    pkiDir = pki;
    endpointOf = new KmsConfig.Endpoint(endpoint.substring(0, endpoint.lastIndexOf(':')),
        Integer.parseInt(endpoint.substring(endpoint.lastIndexOf(':') + 1)));
    graceSeconds = Integer.parseInt(a.getOrDefault("grace-seconds", "3"));
    run = UUID.randomUUID().toString().substring(0, 8);

    Map<String, Scenario> scenarios = new LinkedHashMap<>();
    scenarios.put("grace", ServerProbe::grace);
    scenarios.put("deactivate-predecessors", ServerProbe::deactivatePredecessors);
    scenarios.put("reconcile", ServerProbe::reconcile);
    scenarios.put("retire", ServerProbe::retire);
    scenarios.put("low-level", ServerProbe::lowLevel);
    scenarios.put("legacy", ServerProbe::legacy);
    scenarios.put("sdk-deactivate", ServerProbe::sdkDeactivate);
    scenarios.put("tls", ServerProbe::tls);
    scenarios.put("tls-issue", ServerProbe::tlsIssue);
    scenarios.put("tls-issue-repeat", ServerProbe::tlsIssueRepeat);
    scenarios.put("protection", ServerProbe::protection);
    scenarios.put("names", ServerProbe::names);
    scenarios.put("raw-leases", ServerProbe::rawLeases);

    all = a.getOrDefault("scenarios", "all").equals("all");
    List<String> chosen =
        all ? List.copyOf(scenarios.keySet()) : Arrays.asList(a.get("scenarios").split(","));

    KmsConfig config =
        KmsConfig.builder()
            .endpoints(endpoint)
            .clientIdentityPem(pki.resolve("client.pem"), pki.resolve("client.key"))
            .trustPem(pki.resolve("ca.pem"))
            .minimumVersion(version)
            .maximumVersion(version)
            .callTimeout(Duration.ofSeconds(30))
            .build();
    say("INFO", "probe", "KMIP " + v + " at " + endpoint + ", run " + run + ", SDK from "
        + Kms.class.getProtectionDomain().getCodeSource().getLocation());
    try (Kms k = Kms.connect(config)) {
      kms = k;
      for (String name : chosen) {
        Scenario s = scenarios.get(name.trim());
        if (s == null) throw new IllegalArgumentException("unknown scenario " + name);
        System.out.println("---- [" + v + "] " + name);
        try {
          s.run();
        } catch (Throwable t) {
          check(name + ".unexpected", false, "scenario aborted: " + ex(t));
          t.printStackTrace(System.out);
        }
      }
    }
    System.out.printf("SUMMARY [%s] pass=%d fail=%d info=%d skip=%d%n", v, pass, fail, info, skip);
    System.exit(fail == 0 ? 0 : 1);
  }

  // ---------------------------------------------------------------------------------------------
  // 1. Grace rotation

  static void grace() throws Exception {
    if (!sealing()) return;
    String name = name("grace");
    KeyHandle k0 = aes(name);
    byte[] r0 = sealUnder(k0, PLAINTEXT, aad("r0"));
    KeyHandle rotated;
    boolean scheduled;
    try {
      rotated = k0.rotate(Rotation.grace(Duration.ofSeconds(graceSeconds)));
      scheduled = true;
      check("grace.rotate", true, "rotate(Rotation.grace(" + graceSeconds + "s)) returned " + rotated.id()
          + "; server accepted the client-set Deactivation Date");
    } catch (PartialCompletionException e) {
      scheduled = false;
      check("grace.rotate", false, ex(e));
      rotated = e.created().isEmpty() ? null : e.created().get(0);
      if (rotated == null) return;
    }
    KeyHandle k1 = rotated;
    KeyAttributes a0 = k0.attributes();
    say("INFO", "grace.k0-after-rotate", "k0 " + a0.state() + " deactivationDate="
        + a0.deactivationDate().map(Object::toString).orElse("none") + ", k1 " + state(k1)
        + " deactivationDate=" + k1.attributes().deactivationDate().map(Object::toString).orElse("none"));
    check("grace.k0-active-during-grace", a0.state() == KeyState.ACTIVE, "k0 " + a0.state());
    byte[] rg = null;
    try {
      rg = sealUnder(k0, PLAINTEXT, aad("rg"));
      check("grace.seal-k0-during-grace", true, "sealed under k0 during the grace period");
    } catch (Exception e) {
      check("grace.seal-k0-during-grace", false, ex(e));
    }
    if (!scheduled) {
      say("INFO", "grace.fallback", "no Deactivation Date was set; the guide's fallback:"
          + " k1.deactivatePredecessors() -> " + call(() -> ids(k1.deactivatePredecessors())));
    } else {
      Instant start = Instant.now();
      Instant until = start.plusSeconds(graceSeconds + 20L);
      Thread.sleep((graceSeconds + 1) * 1000L);
      KeyState s;
      while ((s = k0.attributes().state()) == KeyState.ACTIVE && Instant.now().isBefore(until))
        Thread.sleep(500);
      check("grace.k0-deactivated-after-grace", s == KeyState.DEACTIVATED, "k0 " + s + " "
          + Duration.between(start, Instant.now()).toMillis() + " ms after the grace began");
    }
    say("INFO", "grace.states", "k0 " + state(k0) + ", k1 " + state(k1));
    sealRefused("grace.seal-k0-stale-handle", k0);
    sealRefused("grace.seal-k0-fresh-handle", kms.keys().handle(k0.id()));
    opensAll("grace.r0", r0, aad("r0"), name, k1, k0);
    if (rg != null) opensAll("grace.rg", rg, aad("rg"), name, k1, k0);
    try {
      List<KeyHandle> again = k1.deactivatePredecessors();
      check("grace.deactivatePredecessors-after-grace", true, "-> " + ids(again)
          + " (empty expected: k0 is Deactivated already); k0 " + state(k0));
    } catch (Exception e) {
      check("grace.deactivatePredecessors-after-grace", false, ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // 2. deactivatePredecessors (and 3: the old records after each step)

  static void deactivatePredecessors() throws Exception {
    if (!sealing()) return;
    String name = name("deact");
    KeyHandle k0 = aes(name);
    byte[] r0 = sealUnder(k0, PLAINTEXT, aad("r0"));
    KeyHandle k1 = k0.rotate();
    byte[] r1 = sealUnder(k1, PLAINTEXT, aad("r1"));
    KeyHandle k2 = k1.rotate();
    say("INFO", "deact.lineage", "k0 " + k0.id() + " " + state(k0) + " -> k1 " + k1.id() + " " + state(k1)
        + " -> k2 " + k2.id() + " " + state(k2));
    opensAll("deact.before.r0", r0, aad("r0"), name, k2, k0, k1);
    opensAll("deact.before.r1", r1, aad("r1"), name, k2, k1);
    try {
      List<KeyHandle> done = k2.deactivatePredecessors();
      check("deact.call", true, "k2.deactivatePredecessors() -> " + ids(done));
    } catch (Exception e) {
      check("deact.call", false, ex(e));
    }
    expectState("deact.k0", k0, KeyState.DEACTIVATED);
    expectState("deact.k1", k1, KeyState.DEACTIVATED);
    expectState("deact.k2", k2, KeyState.ACTIVE);
    revocationInfo("deact.k0", k0);
    opensAll("deact.after.r0", r0, aad("r0"), name, k2, k0, k1);
    opensAll("deact.after.r1", r1, aad("r1"), name, k2, k1);
    // The SDK's advice for a Compromised record key: open through that key's handle, allowingCompromised().
    say("INFO", "deact.after.r0.via-k0-allowingCompromised",
        call(() -> opened(kms.keys().handle(k0.id()).allowingCompromised().open(r0, aad("r0")))));
    sealRefused("deact.seal-k0", kms.keys().handle(k0.id()));
    try {
      List<KeyHandle> again = k2.deactivatePredecessors();
      check("deact.repeat", again.isEmpty(), "repeat -> " + ids(again) + " (empty expected)");
    } catch (Exception e) {
      check("deact.repeat", false, ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // 4. reconcile, and a fork attempt

  static void reconcile() throws Exception {
    if (!sealing()) return;
    for (String from : List.of("k2", "k0")) {
      String name = name("recon-" + from);
      String p = "reconcile.from-" + from;
      KeyHandle k0 = aes(name);
      byte[] r0 = sealUnder(k0, PLAINTEXT, aad("r0"));
      KeyHandle k1 = k0.rotate();
      KeyHandle k2 = k1.rotate();
      say("INFO", p + ".lineage", "k0 " + state(k0) + ", k1 " + state(k1) + ", k2 " + state(k2));
      try {
        KeyHandle w = (from.equals("k2") ? k2 : k0).reconcile();
        check(p + ".call", w.id().equals(k2.id()), "reconcile() -> " + w.id() + (w.id().equals(k2.id()) ? " (k2)" : " (not k2)"));
      } catch (Exception e) {
        check(p + ".call", false, ex(e));
      }
      // reconcile() revokes every other Active key of the tree as superseded: Deactivated.
      expectState(p + ".k0", k0, KeyState.DEACTIVATED);
      expectState(p + ".k1", k1, KeyState.DEACTIVATED);
      expectState(p + ".k2", k2, KeyState.ACTIVE);
      say("INFO", p + ".names", "k0 " + k0.attributes().names() + ", k1 " + k1.attributes().names()
          + ", k2 " + k2.attributes().names());
      opensAll(p + ".r0", r0, aad("r0"), name, k2, k0);
    }

    // A fork: a second Re-key of a key already replaced.
    String name = name("fork");
    KeyHandle f0 = aes(name);
    byte[] r0 = sealUnder(f0, PLAINTEXT, aad("r0"));
    KeyHandle f1 = f0.rotate();
    say("INFO", "reconcile.fork.sdk-rotate-replaced", "f0.rotate() again -> " + call(() -> f0.rotate().id()));
    Result rk = execute(Requests.reKey().uniqueIdentifier(f0.id()).build());
    say("INFO", "reconcile.fork.low-level-rekey", "Re-key of replaced f0 -> " + describe(rk));
    if (rk.successful()) {
      String f2 = rk.uniqueIdentifier();
      KeyHandle h2 = kms.keys().handle(f2);
      say("INFO", "reconcile.fork.made", "fork f0 -> {f1 " + f1.id() + " " + state(f1) + ", f2 " + f2 + " "
          + state(h2) + "}; f0 replacedBy " + f0.attributes().links());
      say("INFO", "reconcile.fork.reconcile", "f1.reconcile() -> " + call(() -> f1.reconcile().id())
          + "; f0 " + state(f0) + ", f1 " + state(f1) + ", f2 " + state(h2));
      opensAll("reconcile.fork.r0", r0, aad("r0"), name, f1, f0);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // 5. retirePredecessors after re-wrapping

  static void retire() throws Exception {
    if (!sealing()) return;
    for (boolean deactivatedFirst : List.of(false, true)) {
      String p = deactivatedFirst ? "retire.after-deactivate" : "retire.active";
      String name = name(deactivatedFirst ? "retire-d" : "retire-a");
      KeyHandle k0 = aes(name);
      byte[] r0 = sealUnder(k0, PLAINTEXT, aad("r0"));
      KeyHandle k1 = k0.rotate();
      byte[] r1 = sealUnder(k1, PLAINTEXT, aad("r1"));
      KeyHandle k2 = k1.rotate();
      if (deactivatedFirst)
        say("INFO", p + ".deactivatePredecessors", call(() -> ids(k2.deactivatePredecessors()))
            + "; k0 " + state(k0) + ", k1 " + state(k1));
      byte[] w0 = rewrap(p + ".rewrapRecord-r0", () -> kms.keys().current(k2).rewrapRecord(r0, aad("r0")), k2);
      byte[] w1 = rewrap(p + ".rewrapRecordTo-r1", () -> k1.rewrapRecordTo(k2, r1, aad("r1")), k2);
      if (w0 == null || w1 == null)
        say("INFO", p + ".rewrap-failed", "a re-wrap failed; retiring anyway to observe the final states"
            + " (the records not re-wrapped are lost with their keys)");
      try {
        List<KeyHandle> gone = k2.retirePredecessors(RevocationReason.superseded("rotated"));
        check(p + ".call", gone.size() == 2, "retirePredecessors(superseded) -> " + ids(gone));
      } catch (Exception e) {
        check(p + ".call", false, ex(e));
      }
      expectState(p + ".k0", k0, KeyState.DESTROYED);
      expectState(p + ".k1", k1, KeyState.DESTROYED);
      expectState(p + ".k2", k2, KeyState.ACTIVE);
      if (w0 != null) opensAll(p + ".rewrapped-r0", w0, aad("r0"), name, k2);
      if (w1 != null) opensAll(p + ".rewrapped-r1", w1, aad("r1"), name, k2);
      say("INFO", p + ".original-r0-via-k2", call(() -> opened(k2.open(r0, aad("r0"))))
          + " (expected to fail: k0 is destroyed)");
    }
  }

  // ---------------------------------------------------------------------------------------------
  // 6. Low-level controls (3.0)

  static void lowLevel() throws Exception {
    if (!version.atLeast(KmipVersion.V3_0)) {
      skip("low-level", "Deactivate is a KMIP 3.0 operation");
      return;
    }
    String n = name("ll");
    KeyHandle a = plain(n + "-active");
    Result d = execute(Requests.deactivate().uniqueIdentifier(a.id()).build());
    check("low-level.deactivate-active", d.successful() && state(a).equals("DEACTIVATED"),
        "Deactivate on Active -> " + describe(d) + "; state " + state(a));

    KeyHandle pre = kms.keys().createAes(256).named(n + "-pre").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    say("INFO", "low-level.pre-active-created", "state " + state(pre));
    Result dp = execute(Requests.deactivate().uniqueIdentifier(pre.id()).build());
    say("INFO", "low-level.deactivate-pre-active", "Deactivate on Pre-Active -> " + describe(dp) + "; state " + state(pre));

    KeyHandle c = plain(n + "-reason");
    Result dr = execute(Requests.deactivate().uniqueIdentifier(c.id())
        .add(Ttlv.structure(Tag.DEACTIVATION_REASON,
            Ttlv.enumeration(Tag.DEACTIVATION_REASON_CODE, Enums.DeactivationReasonCode.UNSPECIFIED)))
        .build());
    say("INFO", "low-level.deactivate-with-reason", "Deactivate + Deactivation Reason(Unspecified) -> "
        + describe(dr) + "; state " + state(c));

    say("INFO", "low-level.sdk-rotate-deactivated", "rotate() of the Deactivate-d key -> "
        + call(() -> a.rotate().id()));
    Result rk = execute(Requests.reKey().uniqueIdentifier(a.id()).build());
    say("INFO", "low-level.rekey-deactivated", "Re-key of the Deactivate-d key -> " + describe(rk)
        + (rk.successful() ? "; replacement " + rk.uniqueIdentifier() + " " + state(kms.keys().handle(rk.uniqueIdentifier()))
            + " (" + dates(kms.keys().handle(rk.uniqueIdentifier())) + "), old " + state(a) + " (" + dates(a) + ")" : ""));

    KeyHandle r = plain(n + "-noreason");
    Result rn = execute(Requests.revoke().uniqueIdentifier(r.id()).build());
    say("INFO", "low-level.revoke-no-reason", "Revoke without Revocation Reason -> " + describe(rn) + "; state " + state(r)
        + "; " + dates(r));

    KeyHandle s = plain(n + "-superseded");
    Result rs = execute(Requests.revoke(s.id(), Enums.RevocationReasonCode.SUPERSEDED, "probe"));
    say("INFO", "low-level.revoke-superseded", "Revoke(Superseded) -> " + describe(rs) + "; state " + state(s)
        + " (CSD02: Compromised); " + dates(s));

    KeyHandle x = plain(n + "-compromise");
    Thread.sleep(2100); // so the Initial Date and the time of the Revoke differ
    Result rc = execute(Requests.revoke(x.id(), Enums.RevocationReasonCode.KEY_COMPROMISE, "probe"));
    say("INFO", "low-level.revoke-compromise-no-date", "Revoke(Key Compromise) without Compromise Occurrence Date -> "
        + describe(rc) + "; state " + state(x) + "; " + dates(x));
  }

  // ---------------------------------------------------------------------------------------------
  // 7. Legacy compromise rule (1.1, 1.2: Compromise Occurrence Date required); recorded elsewhere

  static void legacy() throws Exception {
    boolean legacy = !version.atLeast(KmipVersion.V1_3);
    String n = name("legacy");
    KeyHandle x = plain(n + "-x");
    Thread.sleep(2100); // so the Initial Date and the time of the Revoke differ
    Result rc = execute(Requests.revoke(x.id(), Enums.RevocationReasonCode.KEY_COMPROMISE, "probe"));
    String what = "low-level Revoke(Key Compromise) without Compromise Occurrence Date -> " + describe(rc)
        + "; state " + state(x);
    if (legacy)
      check("legacy.revoke-compromise-no-date",
          !rc.successful() && rc.hasReason(Enums.ResultReason.MISSING_DATA), what + " (Missing Data expected)");
    else say("INFO", "legacy.revoke-compromise-no-date", what + "; " + dates(x));

    Instant when = Instant.now().minusSeconds(120);
    KeyHandle y = plain(n + "-y");
    try {
      y.revoke(RevocationReason.keyCompromise("probe", when));
      check("legacy.sdk-revoke-compromise", state(y).equals("COMPROMISED"), "revoke(keyCompromise(when=" + when
          + ")) -> state " + state(y) + "; " + dates(y));
    } catch (Exception e) {
      check("legacy.sdk-revoke-compromise", false, ex(e));
    }

    KeyHandle z = plain(n + "-z");
    try {
      KeyHandle z1 = z.replaceCompromised(RevocationReason.keyCompromise("probe", when));
      check("legacy.sdk-replaceCompromised",
          state(z).equals("COMPROMISED") && state(z1).equals("ACTIVE"),
          "replaceCompromised(keyCompromise) -> " + z1.id() + " " + state(z1) + " names " + z1.attributes().names()
              + "; old " + state(z) + "; " + dates(z));
    } catch (Exception e) {
      check("legacy.sdk-replaceCompromised", false, ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Extractable and Sensitive and raw keys for one purpose: what the
  // server does with the attributes, and that the SDK either gets the protection or refuses
  // (never a key that is used without it).

  static void protection() throws Exception {
    if (!version.atLeast(KmipVersion.V1_4)) {
      skip("protection", "Extractable and Sensitive need KMIP 1.4");
      return;
    }
    String name = name("protect");
    KeyHandle kek = null;
    try {
      kek = kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .extractable(false).findOrCreate();
      KeyAttributes a = kek.attributes();
      check("protection.created", a.extractable().equals(java.util.Optional.of(false)) && a.state() == KeyState.ACTIVE,
          "findOrCreate(extractable(false)) -> " + kek.id() + " " + a.state() + ", extractable " + a.extractable()
              + ", sensitive " + a.sensitive());
    } catch (PartialCompletionException | KeyMismatchException | InvalidRequestException | UnsupportedException e) {
      // The documented refusals: the server refused the attribute, or did not keep it.
      check("protection.created-or-refused", true, "refused as documented: " + ex(e));
      say("INFO", "protection.server", "this server does not keep Extractable false");
    }
    if (kek != null) {
      KeyHandle k = kek;
      String got = call(() -> k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
      check("protection.get-refused", got.startsWith("threw"), "asSecretKey of a non-extractable key -> " + got);
      String again = call(() -> kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .extractable(true).findOrCreate().id());
      check("protection.find-never-relaxes", again.startsWith("threw"),
          "findOrCreate(extractable(true)) of the same name -> " + again);
      if (version.atLeast(KmipVersion.V1_4) && sealing()) {
        try {
          KeyHandle next = kek.rotate();
          check("protection.rotate-keeps", next.attributes().extractable().equals(java.util.Optional.of(false)),
              "rotate() -> " + next.id() + ", extractable " + next.attributes().extractable());
        } catch (PartialCompletionException | UnsupportedException e) {
          check("protection.rotate-keeps-or-refuses", true, "refused as documented: " + ex(e));
        }
      }
    }
    // Raw keys for one purpose: an extractable key, Active then Deactivated.
    KeyHandle raw = kms.keys().createAes(256).named(name + "-raw").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    String enc = call(() -> raw.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).getAlgorithm());
    check("protection.encrypt-active", enc.startsWith("ok"), "asSecretKey(aes(), ENCRYPT) of an Active key -> " + enc);
    raw.deactivate();
    KeyHandle deact = kms.keys().handle(raw.id());
    String encD = call(() -> deact.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).getAlgorithm());
    check("protection.encrypt-deactivated-refused", encD.contains("StateConflictException"),
        "asSecretKey(aes(), ENCRYPT) of a Deactivated key -> " + encD);
    String decD = call(() -> deact.asSecretKey(Expect.aes(), LocalUse.DECRYPT).getAlgorithm());
    if (decD.startsWith("ok")) check("protection.decrypt-deactivated", true, "asSecretKey(aes(), DECRYPT) -> " + decD);
    else say("INFO", "protection.decrypt-deactivated", "the server refuses a Deactivated key's value: " + decD);
  }

  // ---------------------------------------------------------------------------------------------
  // Names in use on every version (KMIP 1.x has no reason for one; keytend-kmip-server at 1.4
  // answers Illegal Operation): each path that adds a Name reports AlreadyExistsException once a Locate confirms
  // another holder, and a replacement under a unique name completes.

  static void names() throws Exception {
    String n = name("names");
    KeyHandle held = aes(n);
    KeyHandle other = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    boolean unique;
    try {
      other.addName(n);
      unique = false;
      say("INFO", "names.unique", "the server lets two objects share a name: " + n);
    } catch (AlreadyExistsException e) {
      unique = true;
      check("names.addName", e.getMessage().contains(held.id()) || !version.toString().startsWith("V1"),
          "a duplicate is AlreadyExistsException naming the holder on 1.x: " + ex(e));
    } catch (KmsException e) {
      unique = true;
      check("names.addName", false, "a duplicate is not AlreadyExistsException: " + ex(e));
    }
    if (unique)
      try {
        kms.keys().createAes(256).named(n).usages(KeyUsage.ENCRYPT).create();
        check("names.create", false, "a second key took the name " + n);
      } catch (AlreadyExistsException e) {
        check("names.create", true, "AlreadyExistsException");
      } catch (KmsException e) {
        check("names.create", false, ex(e));
      }
    String sn = name("names-secret");
    KeyHandle old = kms.keys().registerSecret("old".toCharArray()).named(sn).register();
    try {
      KeyHandle next = kms.keys().registerSecret("new".toCharArray()).named(sn).replace(old);
      check("names.replace", kms.keys().findByName(sn).map(KeyHandle::id).orElse("").equals(next.id())
          && !old.attributes().names().contains(sn), "the name moved to " + next.id());
    } catch (KmsException e) {
      check("names.replace", false, ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // One lease rule for raw keys: a key that states a Lease Time is read only after Obtain Lease. A
  // server that leases only Active keys (keytend-kmip-server --lease-states active) refuses a
  // Deactivated one, reported as its state (STATE); under the server's default
  // (active-deactivated) the Deactivated key is leased for decryption, recorded as INFO.

  static void rawLeases() throws Exception {
    String n = name("leases");
    KeyHandle k = aes(n);
    Optional<Duration> lease;
    try {
      lease = k.attributes().leaseTime();
    } catch (KmsException e) {
      check("raw-leases.lease-time", false, ex(e));
      return;
    }
    say("INFO", "raw-leases.lease-time", String.valueOf(lease));
    try {
      k.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).destroy();
      check("raw-leases.active", true, "an Active key is read under its lease");
    } catch (KmsException e) {
      check("raw-leases.active", false, ex(e));
    }
    try {
      k.deactivate();
    } catch (KmsException e) {
      skip("raw-leases.deactivated", "deactivate() refused: " + ex(e));
      return;
    }
    try {
      k.asSecretKey(Expect.aes(), LocalUse.DECRYPT).destroy();
      say("INFO", "raw-leases.deactivated", lease.isPresent()
          ? "the server leased a Deactivated key" : "no Lease Time: no lease needed");
    } catch (StateConflictException e) {
      check("raw-leases.deactivated", lease.isPresent() && "obtainLease".equals(e.operation())
          && e.observedState().orElse(null) == KeyState.DEACTIVATED,
          "a refused lease of a Deactivated key is STATE: " + ex(e));
    } catch (KmsException e) {
      check("raw-leases.deactivated", false, "not reported as the key's state: " + ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // KeyHandle.deactivate(): an Active key becomes Deactivated, never Compromised, on every
  // version, still opens its records through every key of its lineage, and refuses sealing; so do
  // revoke(superseded) and the secret replacement.

  static void sdkDeactivate() throws Exception {
    String name = name("sdk-deact");
    KeyHandle k0 = aes(name);
    byte[] r0 = sealing() ? sealUnder(k0, PLAINTEXT, aad("r0")) : null;
    KeyHandle k1 = r0 != null ? k0.rotate() : null;
    try {
      k0.deactivate();
      check("sdk-deactivate.call", true, "k0.deactivate()");
    } catch (RuntimeException e) {
      check("sdk-deactivate.call", false, ex(e));
    }
    expectState("sdk-deactivate.k0", k0, KeyState.DEACTIVATED);
    if (r0 != null) {
      opensAll("sdk-deactivate.r0", r0, aad("r0"), name, k1, k0);
      sealRefused("sdk-deactivate.seal-k0", kms.keys().handle(k0.id()));
    }
    KeyHandle superseded = aes(name + "-revoked");
    try {
      superseded.revoke(RevocationReason.superseded("retired"));
      check("sdk-deactivate.revoke-superseded", true, "revoke(superseded)");
    } catch (RuntimeException e) {
      check("sdk-deactivate.revoke-superseded", false, ex(e));
    }
    expectState("sdk-deactivate.revoke-superseded", superseded, KeyState.DEACTIVATED);
    KeyHandle secret = kms.keys().registerSecret("hunter2".toCharArray()).named(name + "-secret").register();
    KeyHandle next = kms.keys().registerSecret("correct horse".toCharArray()).named(name + "-secret").replace(secret);
    expectState("sdk-deactivate.secret-old", secret, KeyState.DEACTIVATED);
    expectState("sdk-deactivate.secret-new", next, KeyState.ACTIVE);
    KeyHandle pre = kms.keys().createAes(256).named(name + "-pre").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    say("INFO", "sdk-deactivate.pre-active", "deactivate() of a Pre-Active key -> "
        + call(() -> { pre.deactivate(); return "done"; }) + "; state " + state(pre));
    say("INFO", "sdk-deactivate.repeat", "deactivate() again -> "
        + call(() -> { k0.deactivate(); return "done"; }) + "; state " + state(k0));
  }


  // ---------------------------------------------------------------------------------------------
  // 9. TLS identities (kms.tls()): register, renew, re-key, revoke and re-issue, the links and names
  // they leave, and JSSE handshakes on loopback through the followers' key and trust managers,
  // including the allowlist's check of a peer that has just renewed.

  private static final CustomAttribute TLS_TAG = CustomAttribute.client("probe-tls");

  static void tls() throws Exception {
    String domain = "probe-" + run;
    String serverName = name("tls-server"), clientName = name("tls-client");
    Ca root = Ca.root("Probe Root " + run), issuing = Ca.issued("Probe Issuing CA " + run, root);
    KeyPair serverKey = Ca.ec(), clientKey = Ca.ec();
    X509Certificate serverLeaf = issuing.leaf("probe-server", serverKey.getPublic());
    X509Certificate clientLeaf = issuing.leaf("probe-client", clientKey.getPublic());

    KeyHandle anchor = kms.keys().register(root.certificate).custom(TLS_TAG, domain + ":ca").register(); // usages from Key Usage
    TlsIdentityHandle server, client;
    try {
      server = kms.tls().register(serverKey.getPrivate(), serverLeaf, issuing.certificate).named(serverName)
          .custom(TLS_TAG, domain + ":peer").register();
      client = kms.tls().register(clientKey.getPrivate(), clientLeaf, issuing.certificate).named(clientName)
          .custom(TLS_TAG, domain + ":peer").register();
      check("tls.register", true, "server " + describe(server) + "; client " + describe(client));
    } catch (Exception e) {
      check("tls.register", false, ex(e));
      return;
    }
    links("tls.register", server);

    // Unique names: a second identity, or another kind of object, under the name is refused.
    KeyPair other = Ca.ec();
    try {
      kms.tls().register(other.getPrivate(), issuing.leaf("probe-dup", other.getPublic()), issuing.certificate).named(serverName).register();
      check("tls.register-taken-name", false, "a second identity was registered under " + serverName);
    } catch (AlreadyExistsException e) {
      check("tls.register-taken-name", true, ex(e));
    } catch (Exception e) {
      check("tls.register-taken-name", false, ex(e));
    }
    String keyName = name("tls-aes");
    aes(keyName);
    try {
      kms.tls().register(other.getPrivate(), issuing.leaf("probe-dup2", other.getPublic()), issuing.certificate).named(keyName).register();
      check("tls.register-name-of-a-key", false, "registered under the name of an AES key");
    } catch (AlreadyExistsException e) {
      check("tls.register-name-of-a-key", true, ex(e));
    } catch (Exception e) {
      check("tls.register-name-of-a-key", false, ex(e));
    }

    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "probe-tls");
      t.setDaemon(true);
      return t;
    });
    Duration hourly = Duration.ofHours(1);
    KeyQuery anchors = KeyQuery.all().custom(TLS_TAG, domain + ":ca"), peers = KeyQuery.all().custom(TLS_TAG, domain + ":peer");
    try (TlsIdentityFollower serverId = kms.tls().follow(serverName, hourly, scheduler);
        TlsIdentityFollower clientId = kms.tls().follow(clientName, hourly, scheduler);
        TlsTrustFollower serverTrust = kms.tls().trustAnchors(anchors, peers, hourly, scheduler);
        TlsTrustFollower clientTrust = kms.tls().trustAnchors(anchors, peers, hourly, scheduler);
        Loopback tls = new Loopback(serverId.keyManager(), serverTrust.trustManager())) {
      check("tls.followers", serverTrust.anchors().size() == 1 && serverTrust.allowedPeers().orElseThrow().size() == 2,
          "server " + serverId.status() + ", client " + clientId.status() + ", anchors " + serverTrust.anchors().size()
              + ", allowed peers " + serverTrust.allowedPeers().orElseThrow().size());
      handshake("tls.handshake", tls, clientId.keyManager(), clientTrust, serverLeaf, true);

      // Renew the client (same key): its follower presents the new certificate; the server's
      // trust follower has not refreshed and accepts it by checking the KMS.
      X509Certificate clientRenewed = issuing.leaf("probe-client", clientKey.getPublic());
      try {
        client = client.renew(clientRenewed, issuing.certificate);
        check("tls.renew", client.certificate().attributes().state() == KeyState.ACTIVE, describe(client));
      } catch (Exception e) {
        check("tls.renew", false, ex(e));
      }
      links("tls.renew", client);
      clientId.refresh();
      check("tls.renew.follower", clientId.identity().map(i -> i.certificate().equals(clientRenewed)).orElse(false),
          "client follower " + clientId.status() + " presents the renewed certificate");
      reconnecting("tls.renew.stale-allowlist-accepts", tls, clientId.keyManager(), clientTrust, null);
      check("tls.renew.allowlist-read", serverTrust.allowedPeers().orElseThrow().containsValue(clientRenewed),
          "the server's allowlist now holds the renewed certificate; failure() " + serverTrust.failure().map(ServerProbe::ex).orElse("none"));
      oldLeafLinks("tls.renew", kms.keys().handle(replacedLeaf(client)), client);
      sleepPastGap();
      handshake("tls.renew.old-certificate-refused", tls, held(clientKey.getPrivate(), clientLeaf, issuing.certificate), clientTrust, null, false);

      // Re-key the server: the client's stale trust follower accepts its new certificate.
      KeyPair serverKey2 = Ca.ec();
      X509Certificate serverRekeyed = issuing.leaf("probe-server", serverKey2.getPublic());
      try {
        server = server.rekey(serverKey2.getPrivate(), serverRekeyed, issuing.certificate);
        check("tls.rekey", true, describe(server));
      } catch (Exception e) {
        check("tls.rekey", false, ex(e));
      }
      links("tls.rekey", server);
      serverId.refresh();
      reconnecting("tls.rekey.stale-allowlist-accepts", tls, clientId.keyManager(), clientTrust, serverRekeyed);

      // Certificates that chain to the anchors but are not allowed peers: refused, also after a check.
      KeyPair intruderKey = Ca.ec();
      X509Certificate intruder = issuing.leaf("probe-intruder", intruderKey.getPublic());
      sleepPastGap();
      handshake("tls.unregistered-refused", tls, held(intruderKey.getPrivate(), intruder, issuing.certificate), clientTrust, null, false);
      // Registered with the allowlist's attribute, then revoked, before any follower read it.
      X509Certificate revokedLeaf = issuing.leaf("probe-revoked", intruderKey.getPublic());
      kms.keys().register(revokedLeaf).usages(KeyUsage.VERIFY).custom(TLS_TAG, domain + ":peer").register()
          .revoke(RevocationReason.keyCompromise("probe", Instant.now()));
      sleepPastGap();
      handshake("tls.revoked-unread-refused", tls, held(intruderKey.getPrivate(), revokedLeaf, issuing.certificate), clientTrust, null, false);

      // Revoke the client for a key compromise: it presents nothing, and its kept material is refused.
      try {
        client.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
        check("tls.revoke", true, "certificate " + state(client.certificate()) + ", key " + state(client.privateKey()));
      } catch (Exception e) {
        check("tls.revoke", false, ex(e));
      }
      expectState("tls.revoke.certificate", client.certificate(), KeyState.COMPROMISED);
      expectState("tls.revoke.key", client.privateKey(), KeyState.COMPROMISED);
      TlsIdentityFollower.State s = clientId.refresh();
      check("tls.revoke.follower", s.status() == TlsIdentityFollower.Status.REVOKED && clientId.identity().isEmpty(),
          "client follower " + s);
      serverTrust.refresh();
      sleepPastGap();
      handshake("tls.revoke.kept-material-refused", tls, held(clientKey.getPrivate(), clientRenewed, issuing.certificate), clientTrust, null, false);

      // Re-issue under the name (re-key of the compromised identity): the name comes off the
      // Compromised certificate (Remove Name on a Compromised object), the new pair is accepted at once.
      KeyPair clientKey3 = Ca.ec();
      X509Certificate clientReissued = issuing.leaf("probe-client", clientKey3.getPublic());
      String compromised = client.certificate().id();
      try {
        TlsIdentityHandle found = kms.tls().identity(clientName).orElseThrow();
        check("tls.reissue.identity-of-compromised", found.certificate().id().equals(compromised),
            "identity(name) -> " + found.certificate().id() + " " + state(found.certificate()));
        client = found.rekey(clientKey3.getPrivate(), clientReissued, issuing.certificate);
        check("tls.reissue", true, describe(client));
      } catch (Exception e) {
        check("tls.reissue", false, ex(e));
      }
      List<String> compromisedNames = kms.keys().handle(compromised).attributes().names();
      check("tls.reissue.name-off-compromised", !compromisedNames.contains(clientName),
          "the Compromised certificate's names " + compromisedNames + "; state " + state(kms.keys().handle(compromised)));
      links("tls.reissue", client);
      s = clientId.refresh();
      check("tls.reissue.follower", s.status() == TlsIdentityFollower.Status.CURRENT
          && clientId.identity().map(i -> i.certificate().equals(clientReissued)).orElse(false), "client follower " + s);
      sleepPastGap();
      reconnecting("tls.reissue.stale-allowlist-accepts", tls, clientId.keyManager(), clientTrust, serverRekeyed);

      // The anchors and peers, read once.
      say("INFO", "tls.certificates", "certificates(peers) -> " + call(() -> kms.tls().certificates(peers.state(KeyState.ACTIVE)).size())
          + " Active allowed peers");
    } finally {
      scheduler.shutdownNow();
    }
    say("INFO", "tls.anchor", "anchor " + anchor.id() + " " + state(anchor));
    // The server's own rule for names: another object registered under the identity's name.
    say("INFO", "tls.unique-names.server", "Register of a certificate under the name " + serverName + " (held by "
        + server.certificate().id() + ") -> " + call(() -> kms.keys().register(issuing.leaf("probe-dup3", other.getPublic()))
            .usages(KeyUsage.VERIFY).named(serverName).register().id()));
    tlsDestroyed(issuing);
    tlsLowLevelLinks(issuing);
    tlsLease(root, issuing);
  }

  /**
   * KMIP Lease Time: the followers send Obtain Lease for every object they keep that
   * states one (keytend-kmip-server: {@code --max-lease-seconds}, 3600 s by default, on every
   * object), seen on the wire through a recording transport; a lease the server caps at a Protect
   * Stop Date a few seconds away runs out at use with no request. The next refresh depends on the
   * server's lease policy, and both pass: under {@code --lease-states active} its Obtain Lease is refused and nothing is presented, though the key is still
   * Active; under the default, {@code active-deactivated}, an Active key whose Protect Stop Date
   * has passed is leased again (for its stored Lease Time, up to a Deactivation Date), and the
   * follower presents it again under that lease.
   */
  static void tlsLease(Ca root, Ca issuing) throws Exception {
    String domain = "probe-lease-" + run, n = name("tls-lease");
    KeyHandle anchor = kms.keys().register(root.certificate).custom(TLS_TAG, domain + ":ca").register(); // usages from Key Usage
    KeyPair k = Ca.ec();
    X509Certificate leaf = issuing.leaf("probe-lease", k.getPublic());
    TlsIdentityHandle id = kms.tls().register(k.getPrivate(), leaf, issuing.certificate).named(n)
        .custom(TLS_TAG, domain + ":peer").register();
    List<String> objects = new ArrayList<>(id.chain().stream().map(KeyHandle::id).toList());
    objects.add(id.privateKey().id());
    String keyId = id.privateKey().id();
    Map<String, Object> stated = new LinkedHashMap<>();
    for (String o : objects) stated.put(o, kms.keys().handle(o).attributes().leaseTime().map(Object::toString).orElse("none"));
    stated.put(anchor.id(), anchor.attributes().leaseTime().map(Object::toString).orElse("none"));
    say("INFO", "tls.lease.stated", "Lease Time (Get Attributes) of the leaf, issuing CA, key and anchor: " + stated);
    boolean leasing = !stated.containsValue("none");

    Leases wire = new Leases();
    SSLContext ssl = KmsConfig.sslContextFromPem(pkiDir.resolve("client.pem"), pkiDir.resolve("client.key"), pkiDir.resolve("ca.pem"));
    KmsConfig config = KmsConfig.builder().endpoints(endpointOf.host() + ":" + endpointOf.port())
        .transport(e -> wire.over(new dev.keytend.kmip.transport.TlsTransport(e.host(), e.port(), ssl)))
        .minimumVersion(version).maximumVersion(version).callTimeout(Duration.ofSeconds(30)).build();
    // A stalled executor (its one thread held by a task that waits): no renewal the followers plan
    // runs, so the expiry below is the key manager's own check at use.
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "probe-tls-lease");
      t.setDaemon(true);
      return t;
    });
    java.util.concurrent.CountDownLatch unstall = new java.util.concurrent.CountDownLatch(1);
    scheduler.execute(() -> {
      try {
        unstall.await();
      } catch (InterruptedException stopped) {
        Thread.currentThread().interrupt();
      }
    });
    Duration hourly = Duration.ofHours(1);
    KeyQuery anchors = KeyQuery.all().custom(TLS_TAG, domain + ":ca"), peers = KeyQuery.all().custom(TLS_TAG, domain + ":peer");
    KeyPair serverKey = Ca.ec();
    X509Certificate serverLeaf = issuing.leaf("probe-lease-server", serverKey.getPublic());
    kms.keys().register(serverLeaf).usages(KeyUsage.VERIFY).custom(TLS_TAG, domain + ":peer").register();
    try (Kms leased = Kms.connect(config);
        TlsIdentityFollower f = leased.tls().follow(n, hourly, scheduler)) {
      check("tls.lease.identity-obtained", !leasing || wire.grantedAll(objects),
          (leasing ? "Obtain Lease for leaf, issuing CA and key: " : "the server states no Lease Time; ") + wire.log);
      wire.clear();
      try (TlsTrustFollower t = leased.tls().trustAnchors(anchors, peers, hourly, scheduler);
          Loopback tls = new Loopback(held(serverKey.getPrivate(), serverLeaf, issuing.certificate), t.trustManager())) {
        check("tls.lease.trust-obtained", !leasing || wire.grantedAll(List.of(anchor.id(), id.certificate().id())),
            "Obtain Lease for the anchor and the allowed peers: " + wire.log);
        handshake("tls.lease.handshake", tls, f.keyManager(), t, null, true);
        if (!leasing) {
          skip("tls.lease", "the server states no Lease Time: nothing to lease");
          return;
        }
        // The server caps a lease at the key's Protect Stop Date; once it has passed, it refuses the
        // next one (--lease-states active) or grants it (active-deactivated, the default).
        Instant stop = Instant.ofEpochSecond(Instant.now().getEpochSecond() + 5);
        Result add = execute(Requests.addAttribute().uniqueIdentifier(keyId)
            .attribute(dev.keytend.kmip.model.Attributes.attribute("Protect Stop Date", Ttlv.dateTime(Tag.PROTECT_STOP_DATE, stop)))
            .build());
        say("INFO", "tls.lease.protect-stop-date", "Add Attribute Protect Stop Date " + stop + " on the key " + keyId + " -> " + describe(add));
        if (!add.successful()) {
          skip("tls.lease.expiry", "the server refused a Protect Stop Date; no short lease to observe");
          return;
        }
        wire.clear();
        TlsIdentityFollower.State s = f.refresh();
        Long capped = wire.granted(keyId);
        check("tls.lease.capped", s.status() == TlsIdentityFollower.Status.CURRENT && capped != null && capped > 0 && capped <= 5,
            "refresh " + s + "; " + wire.log);
        wire.clear();
        Thread.sleep(Math.max(0, stop.toEpochMilli() - System.currentTimeMillis()) + 1500);
        int before = wire.requests.get();
        String alias = f.keyManager().chooseServerAlias("EC", null, null);
        check("tls.lease.expired-at-use", alias == null && f.identity().isEmpty() && f.status() == TlsIdentityFollower.Status.STALE
            && wire.requests.get() == before && wire.log.isEmpty(),
            "no refresh since (executor stalled); alias " + alias + ", state " + f.state() + ", requests at use "
                + (wire.requests.get() - before));
        sleepPastGap();
        handshake("tls.lease.expired-handshake-refused", tls, f.keyManager(), t, null, false);
        wire.clear();
        s = f.refresh();
        if (wire.granted(keyId) == null) {
          check("tls.lease.refused", s.status() == TlsIdentityFollower.Status.STALE && s.identity().isEmpty()
                  && wire.refused(keyId) && f.keyManager().chooseServerAlias("EC", null, null) == null,
              "the server refused the lease past the Protect Stop Date (lease policy: Active only); refresh " + s
                  + "; " + wire.log);
        } else {
          Long renewed = wire.granted(keyId);
          check("tls.lease.renewed", s.status() == TlsIdentityFollower.Status.CURRENT && s.identity().isPresent()
                  && (renewed == 0 || renewed > 5) && f.keyManager().chooseServerAlias("EC", null, null) != null,
              "the server leased the Active key past its Protect Stop Date (lease policy: Active and Deactivated;"
                  + " 0 is no limit);"
                  + " refresh " + s + "; " + wire.log);
        }
        expectState("tls.lease.key-still-active", id.privateKey(), KeyState.ACTIVE);
      }
    } catch (Exception e) {
      check("tls.lease", false, ex(e));
    } finally {
      unstall.countDown();
      scheduler.shutdownNow();
    }
  }

  /** Records each Obtain Lease sent through it and the server's answer, by object. */
  static final class Leases {
    final List<String> log = new java.util.concurrent.CopyOnWriteArrayList<>();
    final Map<String, Object> answers = new java.util.concurrent.ConcurrentHashMap<>();
    final java.util.concurrent.atomic.AtomicInteger requests = new java.util.concurrent.atomic.AtomicInteger();

    dev.keytend.kmip.transport.KmipTransport over(dev.keytend.kmip.transport.KmipTransport inner) {
      return new dev.keytend.kmip.transport.KmipTransport() {
        @Override
        public Ttlv exchange(Ttlv request) throws IOException {
          return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
        }

        @Override
        public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context) throws IOException {
          requests.incrementAndGet();
          Ttlv response = inner.exchange(request, context);
          List<Ttlv> items = request.children(Tag.BATCH_ITEM);
          List<Result> results = dev.keytend.kmip.client.Messages.response(response).results();
          for (int i = 0; i < items.size(); i++) {
            if (items.get(i).require(Tag.OPERATION).intValue() != dev.keytend.kmip.model.Operation.OBTAIN_LEASE.code()) continue;
            String id = items.get(i).require(Tag.REQUEST_PAYLOAD).require(Tag.UNIQUE_IDENTIFIER).textValue();
            Result r = i < results.size() ? results.get(i) : null;
            Object answer = r == null ? "no result"
                : r.successful() ? (Object) r.requirePayload().require(Tag.LEASE_TIME).longValue() : describe(r);
            answers.put(id, answer);
            log.add(id + " -> " + (answer instanceof Long l ? "granted " + l + " s" : answer));
          }
          return response;
        }

        @Override
        public void close() throws IOException {
          inner.close();
        }
      };
    }

    void clear() {
      log.clear();
      answers.clear();
    }

    Long granted(String id) {
      return answers.get(id) instanceof Long l ? l : null;
    }

    boolean grantedAll(List<String> ids) {
      for (String id : ids) if (granted(id) == null) return false;
      return true;
    }

    boolean refused(String id) {
      return answers.get(id) instanceof String s && s.contains("PERMISSION_DENIED");
    }
  }

  /**
   * An identity whose certificate and key were destroyed: not found by its name (Locate passes
   * destroyed objects over), so the guide says to register a new one under the name. A server that
   * keeps names on destroyed objects (keytend-kmip-server with {@code --destroyed-name-reuse
   * reserve}) refuses that; one that frees them (the server's
   * default, {@code allow}) accepts it. Either is correct; the check accepts both and says which it saw.
   */
  static void tlsDestroyed(Ca issuing) throws Exception {
    String n = name("tls-destroyed");
    KeyPair k = Ca.ec();
    TlsIdentityHandle h = kms.tls().register(k.getPrivate(), issuing.leaf("probe-destroyed", k.getPublic()), issuing.certificate).named(n).register();
    h.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
    say("INFO", "tls.destroyed.destroy", "destroy leaf -> " + call(() -> { h.certificate().destroy(); return state(h.certificate()); })
        + "; key -> " + call(() -> { h.privateKey().destroy(); return state(h.privateKey()); }));
    // What the name finds before it is registered again: the destroyed identity where Locate returns it.
    Optional<TlsIdentityHandle> found;
    try {
      found = kms.tls().identity(n);
      say("INFO", "tls.destroyed.identity", "identity(name) -> " + found.map(x -> x.certificate().id()));
    } catch (Exception e) {
      found = Optional.empty();
      say("INFO", "tls.destroyed.identity", "identity(name) -> threw " + ex(e));
    }
    for (KeyState st : List.of(KeyState.DESTROYED, KeyState.DESTROYED_COMPROMISED))
      say("INFO", "tls.destroyed.locate-" + st, "Locate(name, state " + st + ") -> "
          + call(() -> kms.keys().list(KeyQuery.byName(n).state(st)).stream().map(KeyHandle::id).toList()));
    say("INFO", "tls.destroyed.locate-any", "Locate(name) -> " + call(() -> kms.keys().list(KeyQuery.byName(n)).stream().map(KeyHandle::id).toList()));
    say("INFO", "tls.destroyed.remove-name", "removeName on the destroyed certificate -> "
        + call(() -> { kms.keys().handle(h.certificate().id()).removeName(n); return "done"; })
        + "; names " + call(() -> kms.keys().handle(h.certificate().id()).attributes().names()));
    // Names reserved: the SDK refuses the name with AlreadyExistsException and leaves nothing Active.
    // Names freed: the registration succeeds and leaves one Active identity under the name.
    KeyPair k2 = Ca.ec();
    X509Certificate again = issuing.leaf("probe-destroyed", k2.getPublic());
    String step = "tls.destroyed.register-again";
    try {
      TlsIdentityHandle made = kms.tls().register(k2.getPrivate(), again, issuing.certificate).named(n).register();
      List<String> active = kms.keys().list(KeyQuery.byName(n).state(KeyState.ACTIVE)).stream().map(KeyHandle::id).toList();
      Optional<String> named = kms.tls().identity(n).map(x -> x.certificate().id());
      boolean one = made.certificate().attributes().state() == KeyState.ACTIVE && made.privateKey().attributes().state() == KeyState.ACTIVE
          && active.equals(List.of(made.certificate().id())) && named.equals(Optional.of(made.certificate().id()));
      check(step, one, "the server frees destroyed names: registered " + describe(made) + "; Active under the name " + active
          + "; identity(name) -> " + named);
    } catch (AlreadyExistsException e) {
      List<String> active = activeUnder(n);
      check(step, active.isEmpty(), "the server keeps destroyed names: " + ex(e) + "; Active objects left with the name or its temporary names " + active);
    } catch (Exception e) {
      check(step, false, ex(e));
    }
    // The destroyed identity is not re-keyed, and nothing is registered: through what the name found
    // before it was registered again, where Locate returned it (1.4 on some servers), else through
    // the handle held. The SDK refuses with StateConflictException (the identity is destroyed, or
    // another one holds the name now) or NotFoundException (no certificate has the name).
    String rekeyStep = found.isPresent() ? "tls.destroyed.rekey-refused" : "tls.destroyed.rekey-held-refused";
    TlsIdentityHandle destroyed = found.orElse(h);
    List<String> before = activeUnder(n);
    try {
      destroyed.rekey(k2.getPrivate(), issuing.leaf("probe-destroyed", k2.getPublic()), issuing.certificate);
      check(rekeyStep, false, "re-keyed a destroyed identity");
    } catch (StateConflictException | NotFoundException e) {
      List<String> after = activeUnder(n);
      check(rekeyStep, after.equals(before), ex(e) + "; Active under the name before " + before + ", after " + after);
    } catch (Exception e) {
      check(rekeyStep, false, ex(e));
    }
  }

  /** The Active objects holding {@code name} itself or one of its temporary names, sorted. */
  private static List<String> activeUnder(String name) {
    return kms.keys().list(KeyQuery.all().state(KeyState.ACTIVE)).stream()
        .filter(x -> x.attributes().names().stream().anyMatch(m -> m.equals(name) || m.startsWith(name + ".issuing-")))
        .map(KeyHandle::id).sorted().toList();
  }

  /**
   * The links the SDK relies on, set one at a time at the protocol layer on fresh objects, so a
   * refusal names the link: a Private Key link on a certificate, a Certificate link on a private key.
   */
  static void tlsLowLevelLinks(Ca issuing) throws Exception {
    KeyPair k = Ca.ec();
    String n = name("tls-links");
    KeyHandle cert = kms.keys().register(issuing.leaf("probe-links", k.getPublic())).usages(KeyUsage.VERIFY).named(n + "-crt").register();
    KeyHandle key = kms.keys().register(k.getPrivate()).usages(KeyUsage.SIGN).named(n + "-key").register();
    say("INFO", "tls.links.private-key-link-on-certificate",
        "Add Attribute Link(Private Key) on a certificate -> " + describe(execute(addLink(cert.id(), Enums.LinkType.PRIVATE_KEY_LINK, key.id())))
            + "; links " + cert.attributes().links());
    say("INFO", "tls.links.certificate-link-on-private-key",
        "Add Attribute Link(Certificate) on a private key -> " + describe(execute(addLink(key.id(), Enums.LinkType.CERTIFICATE_LINK, cert.id())))
            + "; links " + key.attributes().links());
  }

  /**
   * An Add Attribute request of a Link; the client encodes it for the negotiated version (the 3.0
   * draft's typed link attribute on 3.0).
   */
  private static Request addLink(String id, Enums.LinkType type, String target) {
    return Requests.addAttribute().uniqueIdentifier(id).attribute(dev.keytend.kmip.model.Attributes.link(type, target)).build();
  }

  /** The leaf {@code h}'s certificate replaced (its Replaced Object link). */
  private static String replacedLeaf(TlsIdentityHandle h) {
    return h.certificate().attributes().links(LinkKind.REPLACED).get(0);
  }

  /** The replaced leaf after a renewal: Deactivated, without the name, linked to its replacement. */
  private static void oldLeafLinks(String step, KeyHandle old, TlsIdentityHandle h) {
    try {
      KeyAttributes a = old.attributes();
      check(step + ".old-leaf", a.state() == KeyState.DEACTIVATED && a.names().isEmpty()
              && a.links(LinkKind.REPLACEMENT).contains(h.certificate().id()),
          old.id() + " " + a.state() + " names " + a.names() + ", Replacement " + a.links(LinkKind.REPLACEMENT) + "; " + linkAttributes(a));
    } catch (Exception e) {
      check(step + ".old-leaf", false, ex(e));
    }
  }

  /** The trust follower's checks of unknown peers are at least a second apart. */
  private static void sleepPastGap() throws InterruptedException {
    Thread.sleep(1100);
  }

  private static String describe(TlsIdentityHandle h) {
    try {
      KeyAttributes leaf = h.certificate().attributes(), key = h.privateKey().attributes();
      return "leaf " + leaf.id() + " " + leaf.state() + " names " + leaf.names() + ", key " + key.id() + " " + key.state()
          + " names " + key.names() + ", chain " + h.chain().stream().map(KeyHandle::id).toList();
    } catch (Exception e) {
      return "? " + ex(e);
    }
  }

  /** The links between the identity's leaf and key (both ways), and how the server stores them. */
  private static void links(String step, TlsIdentityHandle h) {
    try {
      KeyAttributes leaf = h.certificate().attributes(), key = h.privateKey().attributes();
      boolean pk = leaf.links(LinkKind.PRIVATE_KEY).contains(key.id()), back = key.links(LinkKind.CERTIFICATE).contains(leaf.id());
      check(step + ".links", pk && back, "leaf Private Key link " + leaf.links(LinkKind.PRIVATE_KEY) + ", key Certificate link "
          + key.links(LinkKind.CERTIFICATE) + ", leaf Certificate (issuer) link " + leaf.links(LinkKind.CERTIFICATE)
          + ", Replaced " + leaf.links(LinkKind.REPLACED) + ", Replacement " + leaf.links(LinkKind.REPLACEMENT));
      say("INFO", step + ".link-attributes", "leaf " + linkAttributes(leaf) + "; key " + linkAttributes(key));
      List<String> leftovers = new ArrayList<>();
      for (KeyHandle c : h.chain()) for (String n : c.attributes().names()) if (n.contains(".issuing-")) leftovers.add(c.id() + ":" + n);
      for (String n : key.names()) if (n.contains(".issuing-")) leftovers.add(key.id() + ":" + n);
      check(step + ".no-temporary-names", leftovers.isEmpty(), "temporary names left " + leftovers + "; leaf names " + leaf.names());
    } catch (Exception e) {
      check(step + ".links", false, ex(e));
    }
  }

  /** The protocol attributes about links, by tag name (3.0: the typed link attributes). */
  private static String linkAttributes(KeyAttributes a) {
    List<String> out = new ArrayList<>();
    for (Ttlv t : a.protocolAttributes()) {
      String n = t.tagName();
      if (!n.contains("Link")) continue;
      if (t.type() == Ttlv.Type.STRUCTURE)
        out.add(n + "{" + t.children().stream().map(c -> c.tagName() + "=" + (c.type() == Ttlv.Type.ENUMERATION ? String.valueOf(c.intValue()) : String.valueOf(c.value())))
            .collect(Collectors.joining(",")) + "}");
      else out.add(n + "=" + t.value());
    }
    return out.toString();
  }

  /** A client's handshake with {@code tls}; {@code expected} the server certificate, or null for any. */
  private static void handshake(String step, Loopback tls, KeyManager km, TlsTrustFollower trust, X509Certificate expected, boolean accept) {
    try {
      X509Certificate got = tls.connect(km, trust.trustManager());
      Throwable why = tls.refused.peek();
      tls.refused.clear();
      boolean ok = accept ? got != null && (expected == null || expected.equals(got)) : got == null;
      check(step, ok, (got == null ? "refused" + (why == null ? "" : " (server: " + trunc(String.valueOf(why), 300) + ")")
          : "accepted, server presented " + got.getSubjectX500Principal() + " serial " + got.getSerialNumber().toString(16))
          + (accept ? "" : " (refusal expected)"));
    } catch (Exception e) {
      check(step, false, ex(e));
    }
  }

  /**
   * A peer that has just renewed or re-keyed, before the other side's trust follower refreshed: as
   * a client that reconnects, at most 8 handshakes 600 ms apart. The first is refused at once
   * while the follower checks the KMS in the background, and a later one is accepted once the
   * check read the new certificate.
   */
  private static void reconnecting(String step, Loopback tls, KeyManager km, TlsTrustFollower trust, X509Certificate expected) {
    String first = null;
    for (int attempt = 1; attempt <= 8; attempt++) {
      try {
        X509Certificate got = tls.connect(km, trust.trustManager());
        Throwable why = tls.refused.peek();
        tls.refused.clear();
        if (got != null) {
          boolean ok = expected == null || expected.equals(got);
          check(step, ok, "accepted at handshake " + attempt + ", server presented " + got.getSubjectX500Principal()
              + " serial " + got.getSerialNumber().toString(16) + (first == null ? "" : "; the first was refused: " + first));
          return;
        }
        if (first == null) first = "refused" + (why == null ? "" : " (server: " + trunc(String.valueOf(why), 300) + ")");
        Thread.sleep(600);
      } catch (Exception e) {
        check(step, false, ex(e));
        return;
      }
    }
    check(step, false, "refused at every one of 8 handshakes; the first: " + first);
  }

  /** A key manager holding a fixed key and chain, as a client that kept its material would. */
  private static KeyManager held(PrivateKey key, X509Certificate... chain) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry("held", key, "x".toCharArray(), chain);
    KeyManagerFactory f = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    f.init(store, "x".toCharArray());
    return f.getKeyManagers()[0];
  }

  /** A TLS server on loopback that needs a client certificate and answers each connection with one byte. */
  static final class Loopback implements AutoCloseable {
    final SSLServerSocket socket;
    final java.util.Queue<Throwable> refused = new java.util.concurrent.ConcurrentLinkedQueue<>();

    Loopback(KeyManager km, TrustManager tm) throws Exception {
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
      socket = (SSLServerSocket) ssl.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
      socket.setNeedClientAuth(true);
      Thread loop = new Thread(() -> {
        while (!socket.isClosed()) {
          try (Socket s = socket.accept()) {
            s.setSoTimeout(10000);
            try {
              ((SSLSocket) s).startHandshake();
              s.getOutputStream().write(1);
              s.getOutputStream().flush();
            } catch (IOException e) {
              refused.add(e);
            }
          } catch (IOException closed) {
            // closed
          }
        }
      }, "probe-tls-server");
      loop.setDaemon(true);
      loop.start();
    }

    /** The server's certificate, or null when either side refused. */
    X509Certificate connect(KeyManager km, TrustManager tm) throws Exception {
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
      try (SSLSocket s = (SSLSocket) ssl.getSocketFactory().createSocket(InetAddress.getLoopbackAddress(), socket.getLocalPort())) {
        s.setSoTimeout(10000);
        s.startHandshake();
        InputStream in = s.getInputStream();
        if (in.read() != 1) return null; // TLS 1.3: a refused client certificate is told after the handshake
        return (X509Certificate) s.getSession().getPeerCertificates()[0];
      } catch (IOException e) {
        return null;
      }
    }

    @Override
    public void close() throws IOException {
      socket.close();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // TLS identities the KMS issues (Certify)

  /**
   * An issuing CA the probe registers, an identity the KMS issues with it, a same-key reissue, a
   * new-key reissue and a due reissue, each checked as the SDK documents; a requested validity
   * either honored or refused, never ignored; and an issue without an issuer, which a server with
   * no CA of its own refuses.
   */
  static void tlsIssue() throws Exception {
    // Its own tags: the tls scenario counts the anchors and peers of "probe-" + run.
    String domain = "probe-issue-" + run;
    Ca root = Ca.root("Probe Root " + run), issuing = Ca.issued("Probe Issuing CA " + run, root);
    dev.keytend.kmip.kms.TlsIssuer ca;
    try {
      ca = kms.tls().registerIssuer(issuing.key, issuing.certificate, root.certificate)
          .named(name("tls-issuer")).custom(TLS_TAG, domain + ":ca").register();
      KeyAttributes cert = ca.certificate().attributes(), pub = ca.publicKey().attributes(), key = ca.privateKey().attributes();
      boolean linked = cert.links(LinkKind.PUBLIC_KEY).equals(List.of(pub.id()))
          && pub.links(LinkKind.PRIVATE_KEY).equals(List.of(key.id()))
          && key.usages().contains(KeyUsage.CERTIFICATE_SIGN)
          && cert.state() == KeyState.ACTIVE && pub.state() == KeyState.ACTIVE && key.state() == KeyState.ACTIVE;
      check("tls-issue.register-issuer", linked, ca + ", chain " + ca.chain().stream().map(KeyHandle::id).toList()
          + ", key usages " + key.usages());
    } catch (Exception e) {
      check("tls-issue.register-issuer", false, ex(e));
      return;
    }
    String idName = name("tls-issued");
    TlsIdentityHandle h1;
    try {
      h1 = kms.tls().issue(idName).subject("CN=probe-issued-" + run).dnsNames("localhost").ipAddresses("127.0.0.1")
          .issuedBy(ca).custom(TLS_TAG, domain + ":peer").issue();
      X509Certificate leaf = certificateOf(h1);
      leaf.verify(issuing.certificate.getPublicKey());
      boolean ok = leaf.getSubjectX500Principal().getName().equals("CN=probe-issued-" + run)
          && leaf.getBasicConstraints() == -1
          && h1.chain().size() == 3
          && h1.certificate().attributes().state() == KeyState.ACTIVE
          && h1.privateKey().attributes().state() == KeyState.ACTIVE;
      check("tls-issue.issue", ok, describe(h1) + "; subject " + leaf.getSubjectX500Principal() + ", names "
          + leaf.getSubjectAlternativeNames() + ", valid to " + leaf.getNotAfter().toInstant());
    } catch (Exception e) {
      check("tls-issue.issue", false, ex(e));
      return;
    }
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "probe-tls-issue");
      t.setDaemon(true);
      return t;
    });
    try (TlsIdentityFollower follower = kms.tls().follow(idName, Duration.ofHours(1), scheduler)) {
      check("tls-issue.follow", presents(follower, h1), follower.status() + " " + follower.identity().map(TlsIdentity::certificateId));
      TlsIdentityHandle h2 = h1.reissue();
      boolean same = h2.privateKey().id().equals(h1.privateKey().id())
          && !h2.certificate().id().equals(h1.certificate().id())
          && h1.certificate().attributes().state() == KeyState.DEACTIVATED
          && certificateOf(h2).getPublicKey().equals(certificateOf(h1).getPublicKey());
      check("tls-issue.reissue", same, describe(h2) + "; old leaf " + state(h1.certificate()));
      check("tls-issue.reissue-repeat", h1.reissue().certificate().id().equals(h2.certificate().id()),
          "a repeat from the old handle returns the identity");
      follower.refresh();
      check("tls-issue.follow-reissued", presents(follower, h2), follower.identity().map(TlsIdentity::certificateId).toString());
      TlsIdentityHandle h3 = h2.reissueWithNewKey();
      boolean fresh = !h3.privateKey().id().equals(h2.privateKey().id())
          && h2.privateKey().attributes().state() == KeyState.DEACTIVATED
          && h2.certificate().attributes().state() == KeyState.DEACTIVATED
          && !certificateOf(h3).getPublicKey().equals(certificateOf(h2).getPublicKey());
      check("tls-issue.reissue-new-key", fresh, describe(h3) + "; old key " + state(h2.privateKey()));
      follower.refresh();
      check("tls-issue.follow-new-key", presents(follower, h3), follower.identity().map(TlsIdentity::certificateId).toString());
      TlsIdentityHandle notDue = h3.reissueIfExpiresWithin(Duration.ZERO);
      check("tls-issue.not-due", notDue == h3, "a certificate valid to "
          + certificateOf(h3).getNotAfter().toInstant() + " is not due within 0s");
      TlsIdentityHandle due = h3.reissueIfExpiresWithin(Duration.ofDays(400));
      check("tls-issue.due", !due.certificate().id().equals(h3.certificate().id()), describe(due));
    } catch (Exception e) {
      check("tls-issue.reissue", false, ex(e));
    } finally {
      scheduler.shutdownNow();
    }
    // A requested validity is honored, or the call refuses the certificate: never ignored.
    try {
      TlsIdentityHandle valid = kms.tls().issue(name("tls-issued-valid")).subject("CN=probe-valid-" + run)
          .issuedBy(ca).validFor(Duration.ofHours(12)).issue();
      Instant notAfter = certificateOf(valid).getNotAfter().toInstant();
      boolean near = Duration.between(Instant.now().plus(Duration.ofHours(12)), notAfter).abs().toMinutes() < 6;
      check("tls-issue.validity", near, "honored: valid to " + notAfter);
      // A same-key reissue with another validity: honored too.
      TlsIdentityHandle shorter = valid.reissue(dev.keytend.kmip.kms.TlsReissue.sameKey().validFor(Duration.ofHours(6)));
      Instant end = certificateOf(shorter).getNotAfter().toInstant();
      check("tls-issue.validity-reissue",
          Duration.between(Instant.now().plus(Duration.ofHours(6)), end).abs().toMinutes() < 6
              && shorter.certificate().attributes().state() == KeyState.ACTIVE,
          "honored: valid to " + end + ", " + shorter.certificate().attributes().state());
    } catch (UnsupportedException e) {
      check("tls-issue.validity", e.getMessage().contains("does not honor"), "refused, not ignored: " + ex(e));
    } catch (Exception e) {
      check("tls-issue.validity", false, ex(e));
    }
    // A validity past the issuing CA's notAfter: the SDK refuses it before anything is changed.
    String pastName = name("tls-issued-past-ca");
    try {
      Duration past = Duration.between(Instant.now(), issuing.certificate.getNotAfter().toInstant()).plusDays(1);
      kms.tls().issue(pastName).subject("CN=probe-past-" + run).issuedBy(ca).validFor(past).issue();
      check("tls-issue.validity-past-ca", false, "issued a certificate that outlives its CA");
    } catch (InvalidRequestException e) {
      check("tls-issue.validity-past-ca",
          e.getMessage().contains("issuing CA's notAfter") && kms.tls().identity(pastName).isEmpty(),
          "refused before anything changed: " + ex(e));
    } catch (Exception e) {
      check("tls-issue.validity-past-ca", false, ex(e));
    }
    // Without an issuer in the KMS: only a server with a CA of its own issues.
    try {
      TlsIdentityHandle own = kms.tls().issue(name("tls-issued-server-ca")).subject("CN=probe-own-" + run).issue();
      say("INFO", "tls-issue.server-ca", "the server's own CA issued " + certificateOf(own).getIssuerX500Principal());
    } catch (PartialCompletionException e) {
      check("tls-issue.server-ca", e.getCause() instanceof KmsException,
          "refused (no CA of its own); the key pair " + e.created().stream().map(KeyHandle::id).toList()
              + " is left over: " + ex(e.getCause()));
    } catch (Exception e) {
      check("tls-issue.server-ca", false, ex(e));
    }
  }

  // ---------------------------------------------------------------------------------------------
  // A Certify issue or reissue stopped at each of its writes, and repeated (tls-issue-repeat)

  enum IssueOp {
    ISSUE("issue"),
    REISSUE("reissue"),
    REISSUE_NEW_KEY("reissue-new-key");

    final String step;

    IssueOp(String step) {
      this.step = step;
    }
  }

  /** How the call stops: dead (the process ends) or a dropped connection, before or after the server. */
  enum StopMode {
    DEAD_BEFORE("dead-before", true, false),
    DEAD_AFTER("dead-after", true, true),
    DROP_BEFORE("drop-before", false, false),
    DROP_AFTER("drop-after", false, true);

    final String step;
    final boolean dead, after;

    StopMode(String step, boolean dead, boolean after) {
      this.step = step;
      this.dead = dead;
      this.after = after;
    }
  }

  /** The process stopping dead mid-call: nothing in the SDK catches it. */
  static final class Stop extends Error {
    private static final long serialVersionUID = 1L;

    Stop() {
      super("stopped", null, false, false);
    }
  }

  private static final java.util.Set<Integer> WRITES = java.util.Set.of(
      dev.keytend.kmip.model.Operation.REGISTER.code(), dev.keytend.kmip.model.Operation.ADD_ATTRIBUTE.code(),
      dev.keytend.kmip.model.Operation.MODIFY_ATTRIBUTE.code(), dev.keytend.kmip.model.Operation.DELETE_ATTRIBUTE.code(),
      dev.keytend.kmip.model.Operation.SET_ATTRIBUTE.code(), dev.keytend.kmip.model.Operation.ACTIVATE.code(),
      dev.keytend.kmip.model.Operation.REVOKE.code(), dev.keytend.kmip.model.Operation.DEACTIVATE.code(),
      dev.keytend.kmip.model.Operation.DESTROY.code(), dev.keytend.kmip.model.Operation.RE_KEY.code(),
      dev.keytend.kmip.model.Operation.CREATE_KEY_PAIR.code(), dev.keytend.kmip.model.Operation.CERTIFY.code(),
      dev.keytend.kmip.model.Operation.RE_CERTIFY.code());

  /**
   * A transport wrapper that stops the call at its {@code stopAt}-th write (a request with an item
   * that changes an object), before the server sees it or after the server answered it, and
   * records every write's operations, the objects the server's answers named as made, and which of
   * those answers the client received.
   */
  static final class Stopper {
    final int stopAt;
    final StopMode mode;
    final List<String> writes = new ArrayList<>();
    final java.util.Set<String> made = new java.util.LinkedHashSet<>(), seen = new java.util.LinkedHashSet<>();
    volatile boolean stopped;
    Runnable afterWrite = () -> {};

    Stopper(int stopAt, StopMode mode) {
      this.stopAt = stopAt;
      this.mode = mode;
    }

    dev.keytend.kmip.transport.KmipTransport over(dev.keytend.kmip.transport.KmipTransport inner) {
      return new dev.keytend.kmip.transport.KmipTransport() {
        @Override
        public Ttlv exchange(Ttlv request) throws IOException {
          return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
        }

        @Override
        public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context) throws IOException {
          List<String> ops = new ArrayList<>();
          for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
            int op = item.require(Tag.OPERATION).intValue();
            if (WRITES.contains(op)) ops.add(dev.keytend.kmip.model.Operation.fromCode(op).name());
          }
          boolean write = !ops.isEmpty(), here;
          synchronized (Stopper.this) {
            if (write) writes.add(String.join("+", ops));
            here = write && writes.size() == stopAt && !stopped;
            if (here) stopped = true;
          }
          if (here && !mode.after) throw stop(inner);
          Ttlv response = inner.exchange(request, context);
          java.util.Set<String> named = new java.util.LinkedHashSet<>();
          for (Ttlv item : response.children(Tag.BATCH_ITEM)) {
            int op = item.child(Tag.OPERATION).map(Ttlv::intValue).orElse(-1);
            if (op != dev.keytend.kmip.model.Operation.CREATE_KEY_PAIR.code()
                && op != dev.keytend.kmip.model.Operation.CERTIFY.code()
                && op != dev.keytend.kmip.model.Operation.REGISTER.code()) continue;
            item.child(Tag.RESPONSE_PAYLOAD).ifPresent(p -> {
              for (Tag t : List.of(Tag.UNIQUE_IDENTIFIER, Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER, Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER))
                p.child(t).ifPresent(id -> named.add(id.textValue()));
            });
          }
          made.addAll(named);
          if (here) throw stop(inner);
          seen.addAll(named);
          if (write) afterWrite.run();
          return response;
        }

        @Override
        public void close() throws IOException {
          inner.close();
        }
      };
    }

    private IOException stop(dev.keytend.kmip.transport.KmipTransport inner) {
      if (mode.dead) throw new Stop();
      try {
        inner.close();
      } catch (IOException ignored) {
        // Dropped either way.
      }
      return new IOException("connection dropped by the probe at write " + stopAt + (mode.after ? ", after the server answered" : ""));
    }
  }

  /**
   * For each of issue, same-key reissue and new-key reissue, and each way of stopping (the process
   * stopping dead, or the connection dropping, before the server processes the write or after it
   * answered): the call stops at its first write, then its second, and so on until it completes.
   * After each stop a new Kms repeats the call, and must reach the end state of a call that did not
   * stop (the identity's objects, their states, names and links); a follower refreshed after every
   * write and after the repeat never presents a certificate without its key; and what the stopped
   * call made and the identity does not hold is left over as the SDK documents: not Active (but a
   * private key no Active certificate certifies), named only with the call's temporary name, linked
   * from nothing of the identity, and, when the call threw, named by its exception if the client
   * had seen it.
   *
   * <p>In {@code all} it runs from KMIP 1.4: at 1.1 and 1.2 the three calls send the same writes as
   * at 1.4, and each version takes a few minutes. Named, it runs at any version.
   */
  static void tlsIssueRepeat() throws Exception {
    if (all && !version.atLeast(KmipVersion.V1_4)) {
      skip("tls-issue-repeat", "in all from KMIP 1.4, whose writes 1.1 and 1.2 send too; name the"
          + " scenario to run it at " + v);
      return;
    }
    tlsIssueRepeat("tls-issue-repeat", "tls-repeat", StopMode.values());
  }

  /**
   * Each call stopped each way in {@code modes}, the steps named after {@code scenario} and the
   * objects after {@code prefix}.
   */
  private static void tlsIssueRepeat(String scenario, String prefix, StopMode... modes)
      throws Exception {
    Ca root = Ca.root("Probe " + scenario + " Root " + run);
    Ca issuing = Ca.issued("Probe " + scenario + " CA " + run, root);
    String issuerName = name(prefix + "-issuer");
    dev.keytend.kmip.kms.TlsIssuer ca;
    try {
      ca = kms.tls().registerIssuer(issuing.key, issuing.certificate, root.certificate).named(issuerName).register();
    } catch (Exception e) {
      check(scenario + ".register-issuer", false, ex(e));
      return;
    }
    SSLContext ssl = KmsConfig.sslContextFromPem(pkiDir.resolve("client.pem"), pkiDir.resolve("client.key"), pkiDir.resolve("ca.pem"));
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread t = new Thread(r, "probe-" + scenario);
      t.setDaemon(true);
      return t;
    });
    try {
      for (IssueOp op : IssueOp.values()) {
        String reference;
        String refName = name(prefix + "-" + op.step + "-ref");
        try (Kms fresh = Kms.connect(plainConfig(ssl))) {
          TlsIdentityHandle start = op == IssueOp.ISSUE ? null : issueFor(fresh, refName, issuerName);
          TlsIdentityHandle done = runIssue(fresh, op, refName, issuerName, start);
          reference = shape(fresh, refName, done, start, ca, java.util.Set.of(), new ArrayList<>());
        }
        say("INFO", scenario + "." + op.step + ".reference", reference);
        for (StopMode mode : modes)
          repeatEach(scenario, prefix, op, mode, ssl, scheduler, issuerName, ca, reference);
      }
    } finally {
      scheduler.shutdownNow();
    }
  }

  private static void repeatEach(String scenario, String prefix, IssueOp op, StopMode mode,
      SSLContext ssl, ScheduledExecutorService scheduler, String issuerName,
      dev.keytend.kmip.kms.TlsIssuer ca, String reference) throws Exception {
    String step = scenario + "." + op.step + "." + mode.step;
    List<String> faults = new ArrayList<>(), followerFaults = new ArrayList<>(), leftoverFaults = new ArrayList<>();
    Map<String, Integer> thrown = new java.util.TreeMap<>();
    List<String> writes = List.of();
    int stops = 0, leftovers = 0;
    List<String> certifyLinks = new ArrayList<>();
    for (int n = 1; n < 80; n++) {
      String idName = name(prefix + "-" + op.step + "-" + mode.step + "-" + n);
      Stopper stopper = new Stopper(n, mode);
      KmsConfig stopping = KmsConfig.builder().endpoints(endpointOf.host() + ":" + endpointOf.port())
          .transport(e -> stopper.over(pooled(e, ssl)))
          .minimumVersion(version).maximumVersion(version).retryPolicy(dev.keytend.kmip.kms.RetryPolicy.none())
          .callTimeout(Duration.ofSeconds(30)).build();
      Following follower = new Following(idName, scheduler);
      try (Kms job = Kms.connect(stopping);
          Kms fresh = Kms.connect(plainConfig(ssl));
          follower) {
        TlsIdentityHandle start = op == IssueOp.ISSUE ? null : issueFor(kms, idName, issuerName);
        // The handles a process holds before the call: on the stopping Kms, and on the new one.
        TlsIdentityHandle mine = start == null ? null : job.tls().identity(idName).orElseThrow();
        TlsIdentityHandle theirs = start == null ? null : fresh.tls().identity(idName).orElseThrow();
        int at = n;
        // Never into the call: what the follower does is recorded, not thrown.
        stopper.afterWrite = () -> {
          try {
            String f = followerFault(follower);
            if (f != null) followerFaults.add("write " + at + ": " + f);
          } catch (RuntimeException e) {
            followerFaults.add("write " + at + ": the follower threw " + ex(e));
          }
        };
        Throwable failure = null;
        boolean completed;
        try {
          runIssue(job, op, idName, issuerName, mine);
          completed = true;
        } catch (Stop s) {
          completed = false;
        } catch (KmsException e) {
          completed = false;
          failure = e;
        }
        writes = List.copyOf(stopper.writes);
        if (!stopper.stopped) {
          if (!completed) faults.add("write " + n + ": failed without a stop: " + ex(failure));
          break;
        }
        stops++;
        if (failure != null) thrown.merge(failure.getClass().getSimpleName(), 1, Integer::sum);
        else if (completed) thrown.merge("returned", 1, Integer::sum);
        String f = followerFault(follower);
        if (f != null) followerFaults.add("write " + n + " (after the stop): " + f);
        TlsIdentityHandle done;
        try {
          done = runIssue(fresh, op, idName, issuerName, theirs);
        } catch (Exception e) {
          faults.add("write " + n + ": the repeat failed: " + ex(e));
          continue;
        }
        String got = shape(fresh, idName, done, start, ca, stopper.made, op == IssueOp.REISSUE ? certifyLinks : null);
        if (!got.equals(reference)) faults.add("write " + n + ": " + got);
        f = followerFault(follower);
        if (f != null) followerFaults.add("write " + n + " (after the repeat): " + f);
        else if (follower.f == null || !presents(follower.f, done))
          followerFaults.add("write " + n + ": after the repeat the follower presents "
              + (follower.f == null ? "nothing" : follower.f.identity().map(TlsIdentity::certificateId)) + ", not "
              + done.certificate().id());
        // Then the identity stays usable: a later reissue succeeds and is what the name leads to.
        try {
          TlsIdentityHandle next = op == IssueOp.REISSUE_NEW_KEY ? done.reissueWithNewKey() : done.reissue();
          String now = fresh.tls().identity(idName).orElseThrow().certificate().id();
          if (!now.equals(next.certificate().id())) faults.add("write " + n + ": after a later reissue the name leads to " + now);
        } catch (Exception e) {
          faults.add("write " + n + ": a later reissue failed: " + ex(e));
        }
        // What the stopped call made that the identity does not hold.
        java.util.Set<String> held = new java.util.HashSet<>(roles(fresh, done, start, ca).keySet());
        java.util.Set<String> left = new java.util.LinkedHashSet<>(stopper.made);
        left.removeAll(held);
        leftovers += left.size();
        String report = failure == null ? null : ex(failure);
        for (String id : left) {
          String why = leftoverFault(fresh, id, idName, left, held, done);
          if (why == null && report != null && stopper.seen.contains(id) && !report.contains(id))
            why = "not named by the exception, " + report;
          if (why != null) leftoverFaults.add("write " + n + ": " + id + " " + why);
        }
      }
    }
    String summary = stops + " stops at writes 1.." + stops + " of " + writes.size() + " " + writes;
    check(step, faults.isEmpty() && stops > 0, summary + "; the call threw " + thrown
        + (faults.isEmpty() ? ", and each repeat from a new Kms reached the reference end state" : "; " + faults));
    check(step + ".follower", followerFaults.isEmpty(), followerFaults.isEmpty()
        ? "after every write, stop and repeat, the follower presented nothing or a certificate with its key"
        : followerFaults.toString());
    check(step + ".leftovers", leftoverFaults.isEmpty(), leftovers + " objects left over"
        + (leftoverFaults.isEmpty() ? ", each as documented" : ": " + leftoverFaults)
        + (op == IssueOp.REISSUE ? "; Certify linked the identity's public key to " + certifyLinks.size()
            + " leftover certificates (Certificate links), none Active" : ""));
  }

  /**
   * A transport that pools its connections, as a Kms's own does. Without a pool each request opens
   * a TLS connection, and each stop took about ten times as long. A dropped connection closes the
   * whole transport, its pool with it.
   */
  private static dev.keytend.kmip.transport.TlsTransport pooled(KmsConfig.Endpoint e,
      SSLContext ssl) {
    return dev.keytend.kmip.transport.TlsTransport.builder(e.host(), e.port(), ssl)
        .pool(4, Duration.ofSeconds(30)).build();
  }

  private static KmsConfig plainConfig(SSLContext ssl) {
    return KmsConfig.builder().endpoints(endpointOf.host() + ":" + endpointOf.port())
        .transport(e -> pooled(e, ssl))
        .minimumVersion(version).maximumVersion(version).callTimeout(Duration.ofSeconds(30)).build();
  }

  private static TlsIdentityHandle issueFor(Kms k, String idName, String issuerName) {
    return k.tls().issue(idName).subject("CN=" + idName).dnsNames("localhost").ipAddresses("127.0.0.1")
        .issuedBy(k.tls().issuer(issuerName).orElseThrow()).issue();
  }

  private static TlsIdentityHandle runIssue(Kms k, IssueOp op, String idName, String issuerName, TlsIdentityHandle from) {
    return switch (op) {
      case ISSUE -> issueFor(k, idName, issuerName);
      case REISSUE -> from.reissue();
      case REISSUE_NEW_KEY -> from.reissueWithNewKey();
    };
  }

  /** The identity's objects after a call, and the issuer's, by role. */
  private static Map<String, String> roles(Kms k, TlsIdentityHandle done, TlsIdentityHandle start,
      dev.keytend.kmip.kms.TlsIssuer ca) {
    Map<String, String> roles = new LinkedHashMap<>();
    roles.put(done.certificate().id(), "leaf");
    roles.put(done.privateKey().id(), "key");
    for (String p : k.keys().handle(done.privateKey().id()).attributes().links(LinkKind.PUBLIC_KEY)) roles.putIfAbsent(p, "pub");
    if (start != null) {
      roles.putIfAbsent(start.certificate().id(), "old-leaf");
      roles.putIfAbsent(start.privateKey().id(), "old-key");
      for (String p : k.keys().handle(start.privateKey().id()).attributes().links(LinkKind.PUBLIC_KEY)) roles.putIfAbsent(p, "old-pub");
    }
    roles.putIfAbsent(ca.certificate().id(), "ca");
    roles.putIfAbsent(ca.publicKey().id(), "ca-pub");
    roles.putIfAbsent(ca.privateKey().id(), "ca-key");
    for (KeyHandle c : ca.chain()) roles.putIfAbsent(c.id(), "ca-chain");
    return roles;
  }

  /**
   * The end state of a call, by role: each object of the identity (and what a reissue replaced),
   * its state, names (the identity's name as NAME) and links (to roles, to what the stopped call
   * left over, or to another object), which an interrupted call repeated must reproduce. With
   * {@code certifyLinks}, a same-key reissue's: the public key's Certificate links to leftover
   * certificates that are not Active, which Certify made, are collected there instead.
   */
  private static String shape(Kms k, String idName, TlsIdentityHandle done, TlsIdentityHandle start,
      dev.keytend.kmip.kms.TlsIssuer ca, java.util.Set<String> leftover, List<String> certifyLinks) {
    Map<String, String> roles = roles(k, done, start, ca);
    for (String id : leftover) roles.putIfAbsent(id, "leftover");
    StringBuilder b = new StringBuilder();
    for (Map.Entry<String, String> e : roles.entrySet()) {
      if (e.getValue().startsWith("ca") || e.getValue().equals("leftover")) continue;
      KeyAttributes a = k.keys().handle(e.getKey()).attributes();
      String role = e.getValue();
      List<String> names = a.names().stream().map(x -> x.replace(idName, "NAME")).sorted().toList();
      List<String> links = new ArrayList<>();
      for (dev.keytend.kmip.kms.Link l : a.links()) {
        String to = roles.getOrDefault(l.targetId(), "other");
        if (certifyLinks != null && role.equals("pub") && l.kind() == LinkKind.CERTIFICATE && to.equals("leftover")
            && k.keys().handle(l.targetId()).attributes().state() != KeyState.ACTIVE) {
          certifyLinks.add(l.targetId());
          continue;
        }
        links.add((l.kind() == null ? "type " + l.rawType() : l.kind().name()) + "->" + to);
      }
      java.util.Collections.sort(links);
      b.append(b.length() == 0 ? "" : "; ").append(e.getValue()).append(' ').append(a.state())
          .append(" names ").append(names).append(" links ").append(links);
    }
    try {
      X509Certificate leaf = certificateOf(done);
      if (!leaf.getSubjectX500Principal().getName().equals("CN=" + idName)) b.append("; subject ").append(leaf.getSubjectX500Principal());
    } catch (RuntimeException e) {
      b.append("; leaf unreadable: ").append(ex(e));
    }
    return b.toString();
  }

  /** Why {@code id}, left over by a stopped call, is not as documented; null when it is. */
  private static String leftoverFault(Kms k, String id, String idName, java.util.Set<String> left,
      java.util.Set<String> held, TlsIdentityHandle done) {
    KeyAttributes a;
    try {
      a = k.keys().handle(id).attributes();
    } catch (NotFoundException e) {
      return "is gone";
    }
    for (String n : a.names())
      if (!n.startsWith(idName + ".issuing-")) return "is named " + n;
    for (String h : held) {
      if (h.equals(id)) continue;
      try {
        for (dev.keytend.kmip.kms.Link l : k.keys().handle(h).attributes().links())
          if (l.targetId().equals(id) && (h.equals(done.certificate().id()) || h.equals(done.privateKey().id())))
            return "is linked from the identity's " + h + " (" + l.kind() + ")";
      } catch (NotFoundException ignored) {
        // Not the identity's any more.
      }
    }
    if (a.state() != KeyState.ACTIVE) return null;
    if (a.kind() != dev.keytend.kmip.kms.ObjectKind.PRIVATE_KEY) return "is " + a.kind() + " " + a.state();
    // A private key the call activated to sign its request: no Active certificate may certify it.
    for (String other : left) {
      KeyAttributes c = k.keys().handle(other).attributes();
      if (c.kind() == dev.keytend.kmip.kms.ObjectKind.CERTIFICATE && c.state() == KeyState.ACTIVE)
        return "is an Active private key, and the leftover certificate " + other + " is Active";
    }
    return null;
  }

  /** A follower of an identity's name, made once a certificate has the name (on the probe's Kms). */
  static final class Following implements AutoCloseable {
    final String name;
    final ScheduledExecutorService scheduler;
    volatile TlsIdentityFollower f;

    Following(String name, ScheduledExecutorService scheduler) {
      this.name = name;
      this.scheduler = scheduler;
    }

    /**
     * The follower, refreshed; null while it cannot start: no certificate has the name, or the
     * certificate that has it is not Active yet (follow refuses it, and so presents nothing).
     */
    TlsIdentityFollower refreshed() {
      if (f != null) {
        f.refresh();
        return f;
      }
      try {
        f = kms.tls().follow(name, Duration.ofHours(1), scheduler);
      } catch (NotFoundException | StateConflictException e) {
        return null;
      }
      return f;
    }

    @Override
    public void close() {
      if (f != null) f.close();
    }
  }

  /** Why the follower presents a certificate without its key; null when it presents none, or both. */
  private static String followerFault(Following following) {
    TlsIdentityFollower f = following.refreshed();
    if (f == null) return null;
    javax.net.ssl.X509ExtendedKeyManager km = f.keyManager();
    String alias = km.chooseClientAlias(new String[] {"EC", "RSA"}, null, null);
    if (alias == null) return f.identity().isPresent() ? "an identity " + f.identity().get() + " but no alias" : null;
    X509Certificate[] chain = km.getCertificateChain(alias);
    PrivateKey key = km.getPrivateKey(alias);
    if (chain == null || chain.length == 0 || key == null) return "alias " + alias + " without a chain or a key";
    try {
      String algorithm = key.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
      Signature s = Signature.getInstance(algorithm);
      s.initSign(key);
      s.update(PLAINTEXT);
      byte[] signature = s.sign();
      s.initVerify(chain[0].getPublicKey());
      s.update(PLAINTEXT);
      if (!s.verify(signature)) return "certificate " + chain[0].getSubjectX500Principal() + " with another key";
    } catch (java.security.GeneralSecurityException e) {
      return "certificate " + chain[0].getSubjectX500Principal() + " with a key it cannot check: " + e;
    }
    return null;
  }

  private static X509Certificate certificateOf(TlsIdentityHandle h) {
    return h.certificate().asCertificate();
  }

  /** Whether the follower presents {@code h}'s certificate, and its key is that certificate's. */
  private static boolean presents(TlsIdentityFollower f, TlsIdentityHandle h) {
    return f.identity().map(i -> i.certificateId().equals(h.certificate().id())).orElse(false);
  }

  /**
   * A throwaway certificate authority (EC P-256, SHA256withECDSA): X.509 v3 certificates encoded by
   * hand and signed with the JDK, so the probe needs nothing but the SDK jar.
   */
  static final class Ca {
    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime() & 0xffffffffL);
    final X509Certificate certificate;
    final PrivateKey key;

    private Ca(X509Certificate certificate, PrivateKey key) {
      this.certificate = certificate;
      this.key = key;
    }

    static KeyPair ec() throws Exception {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec("secp256r1"));
      return g.generateKeyPair();
    }

    static Ca root(String name) throws Exception {
      KeyPair k = ec();
      return new Ca(sign(name, name, k.getPublic(), k.getPrivate(), true), k.getPrivate());
    }

    static Ca issued(String name, Ca issuer) throws Exception {
      KeyPair k = ec();
      return new Ca(sign(name, cn(issuer), k.getPublic(), issuer.key, true), k.getPrivate());
    }

    /** A leaf for {@code key}, a new serial number each time. */
    X509Certificate leaf(String name, PublicKey publicKey) throws Exception {
      return sign(name, cn(this), publicKey, key, false);
    }

    private static String cn(Ca ca) {
      String dn = ca.certificate.getSubjectX500Principal().getName();
      return dn.startsWith("CN=") ? dn.substring(3) : dn;
    }

    private static X509Certificate sign(String subject, String issuer, PublicKey key, PrivateKey signer, boolean ca) throws Exception {
      byte[] algorithm = seq(oid("1.2.840.10045.4.3.2"));
      ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
      byte[] validity = seq(utcTime(now.minusDays(1)), utcTime(now.plusDays(2)));
      // Key Usage as real PKIs set it (a CA: keyCertSign and cRLSign; a leaf: digitalSignature),
      // which a KMIP 1.x server maps to the Cryptographic Usage Mask and holds a registration to.
      byte[] keyUsage = seq(oid("2.5.29.15"), tlv(0x01, new byte[] {(byte) 0xff}),
          tlv(0x04, tlv(0x03, ca ? new byte[] {0x01, 0x06} : new byte[] {0x07, (byte) 0x80})));
      byte[] extensions = ca
          ? seq(seq(oid("2.5.29.19"), tlv(0x01, new byte[] {(byte) 0xff}), tlv(0x04, seq(tlv(0x01, new byte[] {(byte) 0xff})))), keyUsage)
          : seq(seq(oid("2.5.29.17"), tlv(0x04, seq(tlv(0x82, "localhost".getBytes(StandardCharsets.US_ASCII)),
              tlv(0x87, new byte[] {127, 0, 0, 1})))), keyUsage);
      byte[] tbs = seq(tlv(0xa0, tlv(0x02, new byte[] {2})), tlv(0x02, BigInteger.valueOf(SERIAL.incrementAndGet()).toByteArray()),
          algorithm, name(issuer), validity, name(subject), key.getEncoded(), tlv(0xa3, extensions));
      Signature s = Signature.getInstance("SHA256withECDSA");
      s.initSign(signer);
      s.update(tbs);
      byte[] signature = s.sign();
      byte[] bits = new byte[signature.length + 1];
      System.arraycopy(signature, 0, bits, 1, signature.length);
      return (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(seq(tbs, algorithm, tlv(0x03, bits))));
    }

    private static byte[] name(String cn) {
      return seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, cn.getBytes(StandardCharsets.UTF_8)))));
    }

    private static byte[] utcTime(ZonedDateTime t) {
      return tlv(0x17, t.format(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] oid(String dotted) {
      String[] p = dotted.split("\\.");
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(Integer.parseInt(p[0]) * 40 + Integer.parseInt(p[1]));
      for (int i = 2; i < p.length; i++) {
        long v = Long.parseLong(p[i]);
        byte[] tmp = new byte[10];
        int n = 0;
        do {
          tmp[n++] = (byte) (v & 0x7f);
          v >>= 7;
        } while (v > 0);
        for (int j = n - 1; j >= 0; j--) out.write(tmp[j] | (j > 0 ? 0x80 : 0));
      }
      return tlv(0x06, out.toByteArray());
    }

    private static byte[] seq(byte[]... parts) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      for (byte[] p : parts) out.writeBytes(p);
      return tlv(0x30, out.toByteArray());
    }

    private static byte[] tlv(int tag, byte[] value) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      out.write(tag);
      int n = value.length;
      if (n < 0x80) out.write(n);
      else if (n < 0x100) {
        out.write(0x81);
        out.write(n);
      } else {
        out.write(0x82);
        out.write(n >> 8);
        out.write(n);
      }
      out.writeBytes(value);
      return out.toByteArray();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers

  private static boolean sealing() {
    if (version.atLeast(KmipVersion.V1_4)) return true;
    skip("sealing", "seal/open need KMIP 1.4 (AES-GCM); scenario skipped");
    return false;
  }

  private static String name(String scenario) {
    return "probe-" + run + "-" + scenario;
  }

  private static byte[] aad(String record) {
    return record.getBytes(StandardCharsets.UTF_8);
  }

  private static KeyHandle aes(String name) {
    return kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  private static KeyHandle plain(String name) {
    return aes(name);
  }

  private static String state(KeyHandle h) {
    try {
      return String.valueOf(kms.keys().handle(h.id()).attributes().state());
    } catch (Exception e) {
      return "?(" + ex(e) + ")";
    }
  }

  private static void expectState(String step, KeyHandle h, KeyState expected) {
    String s = state(h);
    check(step + "-state", s.equals(expected.name()), h.id() + " " + s + " (expected " + expected + ")");
  }

  /** The key's revocation-related dates, from the protocol attributes. */
  private static String dates(KeyHandle h) {
    try {
      KeyAttributes a = kms.keys().handle(h.id()).attributes();
      List<String> out = new ArrayList<>();
      for (Ttlv t : a.protocolAttributes()) {
        Optional<Tag> tag = t.standardTag();
        if (tag.isEmpty()) continue;
        switch (tag.get()) {
          case INITIAL_DATE, ACTIVATION_DATE, DEACTIVATION_DATE, COMPROMISE_DATE, COMPROMISE_OCCURRENCE_DATE ->
              out.add(t.tagName() + "=" + t.instantValue());
          case REVOCATION_REASON -> out.add("RevocationReason=" + t.children().stream()
              .map(c -> c.tagName() + ":" + (c.type() == Ttlv.Type.ENUMERATION ? enumName(c) : String.valueOf(c.value())))
              .collect(Collectors.joining(",")));
          default -> {}
        }
      }
      return String.join(" ", out);
    } catch (Exception e) {
      return "dates ?(" + ex(e) + ")";
    }
  }

  private static String enumName(Ttlv c) {
    if (c.standardTag().orElse(null) == Tag.REVOCATION_REASON_CODE)
      return Enums.RevocationReasonCode.fromCode(c.intValue()).map(Enum::name).orElse("0x" + Integer.toHexString(c.intValue()));
    return String.valueOf(c.intValue());
  }

  private static void revocationInfo(String step, KeyHandle h) {
    say("INFO", step + ".attributes", dates(h));
  }

  private static void sealRefused(String step, KeyHandle h) {
    try {
      // One Encrypt under exactly h, as sealing sends; a CurrentKey would follow the refusal.
      h.encrypt(CipherSpec.aesGcm(), PLAINTEXT, aad("refused"));
      check(step, false, "sealed under " + h.id() + " (" + state(h) + "): expected a StateConflictException");
    } catch (StateConflictException e) {
      check(step, e.observedState().orElse(null) == KeyState.DEACTIVATED,
          ex(e) + " (observedState DEACTIVATED expected)");
    } catch (Exception e) {
      check(step, false, ex(e));
    }
  }

  /** The record opens through each handle given (the newest first) and through findByName. */
  private static void opensAll(String step, byte[] record, byte[] aad, String name, KeyHandle... via) {
    for (int i = 0; i < via.length; i++) {
      KeyHandle h = via[i];
      opens(step + ".via-" + (i == 0 ? "newest" : "own-" + i) + "(" + h.id() + ")", () -> h.open(record, aad));
    }
    opens(step + ".via-findByName", () -> kms.keys().findByName(name).orElseThrow().open(record, aad));
  }

  private static void opens(String step, ThrowingSupplier<byte[]> open) {
    try {
      byte[] out = open.get();
      check(step, Arrays.equals(out, PLAINTEXT), opened(out));
    } catch (Exception e) {
      check(step, false, ex(e));
    }
  }

  private static String opened(byte[] out) {
    return Arrays.equals(out, PLAINTEXT) ? "opened" : "opened, wrong plaintext";
  }

  /**
   * A record sealed under {@code k}: a follower made now holds {@code k} and checks for a newer key
   * only after a minute, so it seals under {@code k} unless {@code k} is refused.
   */
  private static byte[] sealUnder(KeyHandle k, byte[] plaintext, byte[] aad) {
    byte[] sealed = kms.keys().current(k).seal(plaintext, aad);
    // A refused k would have been followed to a newer key: then this did not seal under k.
    String under = KmsKeys.sealedKeyId(sealed);
    if (!under.equals(k.id()))
      throw new IllegalStateException("sealed under " + under + ", not " + k.id() + " (" + k.id() + " was refused)");
    return sealed;
  }

  private static byte[] rewrap(String step, ThrowingSupplier<Rewrapped> r, KeyHandle target) {
    try {
      Rewrapped w = r.get();
      check(step, w.changed() && w.keyId().equals(target.id()), "changed=" + w.changed() + " keyId=" + w.keyId());
      return w.bytes();
    } catch (Exception e) {
      check(step, false, ex(e));
      return null;
    }
  }

  interface ThrowingSupplier<T> {
    T get() throws Exception;
  }

  private static String call(ThrowingSupplier<?> s) {
    try {
      return "ok: " + s.get();
    } catch (Exception e) {
      return "threw " + ex(e);
    }
  }

  private static Result execute(Request r) throws Exception {
    return kms.protocol().execute(r);
  }

  private static String describe(Result r) {
    if (r.successful()) return "Success";
    return r.statusEnum().map(Enum::name).orElse("status " + r.status()) + "/"
        + r.reasonEnum().map(Enum::name).orElse(r.reason() == null ? "no reason" : "reason " + r.reason())
        + (r.message() == null ? "" : " \"" + trunc(r.message(), 160) + "\"");
  }

  private static String ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).collect(Collectors.toList()).toString();
  }

  static String ex(Throwable t) {
    StringBuilder b = new StringBuilder(t.getClass().getSimpleName());
    if (t instanceof KmsException k) {
      b.append("[").append(k.category());
      k.protocolReason().ifPresent(r -> b.append(" reason=").append(r));
      if (k.protocolReason().isEmpty()) k.reasonCode().ifPresent(r -> b.append(" reasonCode=").append(r));
      if (t instanceof StateConflictException s) s.observedState().ifPresent(o -> b.append(" observed=").append(o));
      if (t instanceof PartialCompletionException p) b.append(" created=").append(ids(p.created()));
      b.append("]");
      k.serverMessage().ifPresent(m -> b.append(" server=\"").append(trunc(m, 120)).append("\""));
    }
    b.append(": ").append(trunc(String.valueOf(t.getMessage()), 400));
    Throwable c = t.getCause();
    if (c != null && c != t) {
      b.append(" <- ").append(c.getClass().getSimpleName());
      if (c instanceof KmsException k) k.protocolReason().ifPresent(r -> b.append("[reason=").append(r).append("]"));
      b.append(": ").append(trunc(String.valueOf(c.getMessage()), 200));
    }
    return b.toString();
  }

  private static String trunc(String s, int n) {
    s = s.replace('\n', ' ');
    return s.length() <= n ? s : s.substring(0, n) + "...";
  }

  private static void check(String step, boolean ok, String detail) {
    say(ok ? "PASS" : "FAIL", step, detail);
  }

  private static void skip(String step, String detail) {
    say("SKIP", step, detail);
  }

  private static void say(String kind, String step, String detail) {
    switch (kind) {
      case "PASS" -> pass++;
      case "FAIL" -> fail++;
      case "INFO" -> info++;
      default -> skip++;
    }
    System.out.println(kind + " [" + v + "] " + step + ": " + detail);
    System.out.flush();
  }

  private static Map<String, String> parse(String[] args) {
    Map<String, String> m = new LinkedHashMap<>();
    for (int i = 0; i < args.length; i++) {
      if (!args[i].startsWith("--") || i + 1 >= args.length) throw new IllegalArgumentException("usage: --endpoint host:port --version 3.0 --pki DIR [--scenarios all|a,b] [--grace-seconds 3]");
      m.put(args[i].substring(2), args[++i]);
    }
    return m;
  }

  private static String need(Map<String, String> a, String key) {
    String s = a.get(key);
    if (s == null) throw new IllegalArgumentException("missing --" + key);
    return s;
  }
}
