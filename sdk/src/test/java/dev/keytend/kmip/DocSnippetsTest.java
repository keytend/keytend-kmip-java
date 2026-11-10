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

package dev.keytend.kmip;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import javax.tools.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Compiles every {@code java} code block of the README and the guides against the SDK. Each block
 * becomes the body of a method in a class whose fields declare the names the examples use without
 * defining (client, keyId, plaintext, ...); a block may declare its own variables of the same
 * names, and its own classes (a complete program, a JUnit test). Lines starting with {@code
 * import} move to the top of the file. Two guides show lines of running code rather than whole
 * statements, and their own tests hold every line to that code: docs/local-keys.md "Transparent
 * data encryption keys" ({@code TdeKeyProviderTest}, against the sample {@code TdeKeyProvider})
 * and docs/tls-identities.md ({@code OperatingTlsGuideTest}).
 */
class DocSnippetsTest {
  private static final String IMPORTS =
      String.join(
          "\n",
          "import dev.keytend.kmip.client.*;",
          "import dev.keytend.kmip.codec.*;",
          "import dev.keytend.kmip.model.*;",
          "import dev.keytend.kmip.server.*;",
          "import dev.keytend.kmip.transport.*;",
          "import java.io.*;",
          "import java.net.*;",
          "import java.nio.charset.*;",
          "import java.nio.file.*;",
          "import java.security.*;",
          "import java.security.cert.X509Certificate;",
          "import java.time.*;",
          "import java.util.*;",
          "import java.util.concurrent.atomic.*;",
          "import java.util.function.*;",
          "import javax.crypto.*;",
          "import javax.crypto.spec.*;",
          "import javax.net.ssl.*;");

  private static final String FIELDS =
      String.join(
          "\n",
          "  KmipClient client;",
          "  String keyId, pubId, publicKeyId, privateKeyId, kekId, id;",
          "  byte[] plaintext, aad, iv, message, signature, ciphertext, dek;",
          "  SSLContext ssl, kmsOnlyContext; char[] password;",
          "  InetSocketAddress bind; CallbackHandler handler; Principal expectedServer;",
          "  X509Certificate certificate; PrivateKey privateKey; PublicKey publicKey;",
          "  SecretKey secretKey;",
          "  interface Log { void warn(String m, Object... args); void info(String m, Object... args); } Log log;",
          // The application's own objects the guides use: a record store, a file's chunks, a
          // manifest.
          "  interface Record { String id(); byte[] sealed(); byte[] aad(); }",
          "  interface Store { Iterable<Record> all(); void put(String id, byte[] value); void writeHeader(byte[] h);",
          "    void writeChunk(long i, byte[] c); byte[] readHeader(); void replaceHeader(byte[] h); byte[] readChunk(long i); } Store store;",
          "  interface Manifest { void add(String id); Collection<String> ids(); } Manifest manifest;",
          "  List<String> quarantine;",
          "  interface Upload { OutputStream start(); void commit(); } Upload upload; InputStream source;",
          "  Path export, backup, restored, certPem, keyPem, caPem; int n; byte[] block(int i) { return null; }",
          "  void writeFile(String keyId, Object value) {}",
          "  String storedKeyId, oldId, newId, oldestStillNeeded, idFromChunkHeader; Instant since; char[] newPassword;");

  /** The JUnit 5 API, for the guides' test examples. */
  private static final String JUNIT = location(org.junit.jupiter.api.Test.class);

  /**
   * The in-memory server (keytend-kmip-testing), which the examples of testing and of trying the
   * SDK out use, as an application adds it beside the SDK: its package's classes alone, copied
   * from the SDK's test classes (which compile them in) to {@code target/snippet-testing}.
   */
  private static final String TESTING = testingClasses();

  private static String testingClasses() {
    String pkg = "dev/keytend/kmip/testing";
    Path from = Path.of(location(dev.keytend.kmip.testing.InMemoryKmipServer.class)).resolve(pkg);
    Path to = Path.of("target/snippet-testing").toAbsolutePath();
    try (var files = Files.list(from)) {
      Files.createDirectories(to.resolve(pkg));
      for (Path f : files.filter(f -> f.toString().endsWith(".class")).toList())
        Files.copy(
            f, to.resolve(pkg).resolve(f.getFileName()), StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
    return to.toString();
  }

  private static String location(Class<?> type) {
    try {
      return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    } catch (java.net.URISyntaxException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The guides whose blocks compile here. */
  static final List<String> DOCS =
      List.of(
          "README.md",
          "docs/getting-started.md",
          "docs/choosing-an-api.md",
          "docs/envelope-encryption.md",
          "docs/local-keys.md",
          "docs/operating-keys.md",
          "docs/production.md",
          "docs/protocol-layer.md",
          "docs/migration.md",
          "docs/in-memory-server.md");

  /**
   * Sections whose blocks other tests hold to running code, line by line, or compile where their
   * library is: production.md's "Metrics" uses the keytend-kmip-micrometer module (its
   * MetricsGuideTest), its "OpenTelemetry" the keytend-kmip-opentelemetry module (its
   * TelemetryGuideTest).
   */
  static final Map<String, List<String>> CHECKED_ELSEWHERE =
      Map.of(
          "docs/local-keys.md", List.of("## Transparent data encryption keys"),
          "docs/production.md", List.of("## Metrics", "## OpenTelemetry"));

  /** The application-API names the guides use without defining. */
  private static final String KMS_FIELDS =
      String.join(
          "\n",
          "  Kms kms; KmsConfig config; KeyHandle key, kek, old, newest, secret; CurrentKey current; LocalKeys keys;",
          "  java.util.concurrent.ScheduledExecutorService scheduler; KeyQuery anchorQuery, allowedPeerQuery;",
          "  byte[] record, recordId, fileId, header, sealed, orderJson, orderId; RevocationReason reason;");

  static List<String> snippets(Path file) throws IOException {
    return snippets(file, List.of());
  }

  /** The {@code java} blocks of {@code file}, without those in the {@code skipped} sections. */
  static List<String> snippets(Path file, List<String> skipped) throws IOException {
    String text = Files.readString(file);
    for (String heading : skipped) {
      int start = text.indexOf("\n" + heading + "\n");
      assertTrue(start >= 0, file + " has the section " + heading);
      int end = text.indexOf("\n## ", start + heading.length() + 1);
      text = text.substring(0, start) + (end < 0 ? "" : text.substring(end));
    }
    List<String> out = new ArrayList<>();
    Matcher m = Pattern.compile("```java\\n(.*?)```", Pattern.DOTALL).matcher(text);
    while (m.find()) out.add(m.group(1));
    return out;
  }

  /**
   * No example builds an SLF4J message by concatenation: {@code log.warn("files " + files, why)}
   * prints neither the value escaped nor {@code why} (a format argument without a placeholder).
   * Values go in as arguments, {@code log.warn("files {}: {}", files, why)}. Every guide in docs/
   * and the README, the sections compiled elsewhere included.
   */
  @Test
  void noExampleConcatenatesALogMessage() throws IOException {
    Path root = Path.of(System.getProperty("project.root", ".."));
    Pattern concatenated =
        Pattern.compile("\\blog\\.(trace|debug|info|warn|error)\\(\"(?:[^\"\\\\]|\\\\.)*\"\\s*\\+");
    List<Path> guides = new ArrayList<>(List.of(root.resolve("README.md")));
    try (var docs = Files.list(root.resolve("docs"))) {
      docs.filter(f -> f.toString().endsWith(".md")).sorted().forEach(guides::add);
    }
    List<String> found = new ArrayList<>();
    for (Path doc : guides)
      for (String block : snippets(doc)) {
        for (String line : block.split("\n"))
          if (concatenated.matcher(line).find()) found.add(doc.getFileName() + ": " + line.strip());
        for (String mismatch : placeholderMismatches(block))
          found.add(doc.getFileName() + ": " + mismatch);
      }
    assertEquals(List.of(), found);
  }

  /**
   * The slf4j-api versions the guides tell users to add or pin are the root POM's: getting
   * started's dependency block and Gradle line (an application installing the SDK from the release
   * adds slf4j-api itself), the logging guide and the dependency list. The release check builds
   * against the block whatever version it names, so a bump of {@code slf4j.version} would leave
   * them stale without this.
   */
  @Test
  void theGuidesNameTheSlf4jVersionsThePomPins() throws IOException {
    Path root = Path.of(System.getProperty("project.root", ".."));
    String pom = Files.readString(root.resolve("pom.xml"));
    Map<String, String> pinned = new HashMap<>();
    for (String property : List.of("slf4j.version", "slf4j17.version")) {
      Matcher m = Pattern.compile("<" + Pattern.quote(property) + ">([^<]+)<").matcher(pom);
      assertTrue(m.find(), "the root POM pins " + property);
      pinned.put(property, m.group(1));
    }
    String[][] mentions = {
      {
        "docs/getting-started.md",
        "<artifactId>slf4j-api</artifactId> <version>([^<]+)</version>",
        "slf4j.version"
      },
      {"docs/getting-started.md", "\"org\\.slf4j:slf4j-api:([^\"]+)\"", "slf4j.version"},
      {"docs/production.md", "The SDK brings slf4j-api ([0-9.]*[0-9])", "slf4j.version"},
      {"docs/production.md", "the SDK's ([0-9.]*[0-9]) \\(nearest wins\\)", "slf4j.version"},
      {"docs/production.md", "pin slf4j-api ([0-9.]*[0-9])", "slf4j17.version"},
      {"docs/dependencies.md", "\\| `org\\.slf4j:slf4j-api` \\| ([^ |]+) \\|", "slf4j.version"},
    };
    List<String> wrong = new ArrayList<>();
    for (String[] mention : mentions) {
      String text = Files.readString(root.resolve(mention[0])).replaceAll("\\s+", " ");
      Matcher m = Pattern.compile(mention[1]).matcher(text);
      int found = 0;
      while (m.find()) {
        found++;
        if (!m.group(1).equals(pinned.get(mention[2])))
          wrong.add(mention[0] + ": " + m.group() + ", not " + pinned.get(mention[2]));
      }
      if (found == 0) wrong.add(mention[0] + ": nothing matches " + mention[1]);
    }
    assertEquals(List.of(), wrong);
  }

  /**
   * The keytend-kmip version users copy or follow (README.md, docs/index.md, getting started and
   * production: Maven and Gradle coordinates, file names, the tag to check out or read the docs
   * at) is the version the POMs build. Step 1 of docs/releasing.md changes both, and the release
   * check's user-commands runs these blocks against the packaged release.
   */
  @Test
  void theGuidesNameTheVersionThePomsBuild() throws IOException {
    Path root = Path.of(System.getProperty("project.root", ".."));
    Matcher building =
        Pattern.compile(
                "<artifactId>keytend-kmip-parent</artifactId>\\s*<version>([^<]+)</version>")
            .matcher(Files.readString(root.resolve("pom.xml")));
    assertTrue(building.find(), "the project version in pom.xml");
    String version = building.group(1).strip();
    String number = "(\\d+\\.\\d+(?:\\.\\d+)?(?:-rc\\.\\d+)?)(?![\\d.]\\d)";
    Pattern mention =
        Pattern.compile(
            "keytend-kmip(?:-(?!server)[a-z]+)?[-:]"
                + number
                + "|<artifactId>keytend-kmip[a-z-]*</artifactId> <version>([^<]+)</version>"
                + "|git checkout v"
                + number
                + "|/tree/v"
                + number);
    List<String> wrong = new ArrayList<>();
    int found = 0;
    for (String file :
        List.of("README.md", "docs/index.md", "docs/getting-started.md", "docs/production.md")) {
      Matcher m = mention.matcher(Files.readString(root.resolve(file)).replaceAll("\\s+", " "));
      while (m.find()) {
        found++;
        String named =
            m.group(1) != null
                ? m.group(1)
                : m.group(2) != null ? m.group(2) : m.group(3) != null ? m.group(3) : m.group(4);
        if (!named.equals(version)) wrong.add(file + ": " + m.group() + ", not " + version);
      }
    }
    assertTrue(found > 20, "the version is named in the guides: " + found);
    assertEquals(List.of(), wrong);
  }

  /** The names an example gives a {@code Throwable}, which SLF4J takes as the last argument. */
  static final Pattern THROWABLE =
      Pattern.compile("e|ex|t|thrown|cause|error|failure|\\w*(Exception|Failure|Error)");

  /**
   * The SLF4J calls of {@code code} whose arguments do not match the message's {@code {}}: one
   * argument per placeholder, and at most one more, a {@code Throwable} (an argument without a
   * placeholder is otherwise dropped from the line).
   */
  static List<String> placeholderMismatches(String code) {
    List<String> out = new ArrayList<>();
    Matcher call =
        Pattern.compile("\\blog\\.(trace|debug|info|warn|error)\\(\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
            .matcher(code);
    while (call.find()) {
      int placeholders = 0;
      for (int i = call.group(2).indexOf("{}"); i >= 0; i = call.group(2).indexOf("{}", i + 2))
        placeholders++;
      List<String> args = new ArrayList<>();
      int depth = 0, start = -1;
      for (int i = call.end(); i < code.length(); i++) {
        char c = code.charAt(i);
        if (c == '"') {
          // A string argument: skip to its end.
          for (i++; i < code.length() && code.charAt(i) != '"'; i++)
            if (code.charAt(i) == '\\') i++;
          continue;
        }
        if (c == '(' || c == '[' || c == '{') depth++;
        else if ((c == ')' || c == ']' || c == '}') && depth > 0) depth--;
        else if (c == ')' || (c == ',' && depth == 0)) {
          if (start >= 0) args.add(code.substring(start, i).strip());
          if (c == ')') break;
          start = i + 1;
        }
      }
      boolean throwable =
          args.size() == placeholders + 1 && THROWABLE.matcher(args.get(args.size() - 1)).matches();
      if (args.size() != placeholders && !throwable)
        out.add(
            "log."
                + call.group(1)
                + "(\""
                + call.group(2)
                + "\") has "
                + placeholders
                + " placeholders and "
                + args.size()
                + " arguments "
                + args);
    }
    return out;
  }

  @Test
  void thePlaceholderCheckFindsAnArgumentWithoutAPlaceholder() {
    assertEquals(
        List.of(),
        placeholderMismatches("log.warn(\"TLS files {} did not load: {}\", files, why);"));
    assertEquals(
        List.of(), placeholderMismatches("log.warn(\"not following {}\", keyId, failure);"));
    assertEquals(List.of(), placeholderMismatches("log.info(\"a {} and {}\", f(a, b), \"x, y\");"));
    assertEquals(1, placeholderMismatches("log.warn(\"TLS files did not load\", why);").size());
    assertEquals(1, placeholderMismatches("log.warn(\"{} and {}\", files);").size());
  }

  @TestFactory
  List<DynamicTest> documentationExamplesCompile() throws IOException {
    Path root = Path.of(System.getProperty("project.root", ".."));
    List<DynamicTest> tests = new ArrayList<>();
    for (String doc : DOCS) {
      List<String> blocks =
          snippets(root.resolve(doc), CHECKED_ELSEWHERE.getOrDefault(doc, List.of()));
      assertFalse(blocks.isEmpty(), doc + " has Java examples");
      for (int i = 0; i < blocks.size(); i++) {
        String code = blocks.get(i);
        String name = doc + " example " + (i + 1);
        int index = i;
        tests.add(DynamicTest.dynamicTest(name, () -> compile(doc, index, code)));
      }
    }
    return tests;
  }

  private static void compile(String doc, int index, String code) throws IOException {
    StringBuilder imports = new StringBuilder(IMPORTS).append('\n');
    String fields = FIELDS;
    if (Files.isDirectory(Path.of("target/classes/dev/keytend/kmip/kms"))) {
      imports.append("import dev.keytend.kmip.kms.*;\n");
      fields += "\n" + KMS_FIELDS;
    }
    StringBuilder body = new StringBuilder();
    for (String line : code.split("\n"))
      if (line.startsWith("import ")) imports.append(line).append('\n');
      else if (line.strip().equals("...")) body.append("// ...\n"); // an elision
      else body.append(line).append('\n');
    String className = "Snippet" + index;
    String source =
        imports
            + "\nclass "
            + className
            + " {\n"
            + fields
            + "\n  void run() throws Exception {\n"
            + body
            + "\n  }\n}\n";
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "tests need a JDK");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    JavaFileObject file =
        new SimpleJavaFileObject(
            URI.create("string:///" + className + ".java"), JavaFileObject.Kind.SOURCE) {
          @Override
          public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
          }
        };
    Path out = Files.createTempDirectory("snippets");
    List<String> options =
        List.of(
            "-classpath",
            Path.of("target/classes").toAbsolutePath()
                + File.pathSeparator
                + JUNIT
                + File.pathSeparator
                + TESTING,
            "-d",
            out.toString(),
            "-proc:none",
            "--release",
            "17",
            "-Xlint:-options");
    boolean ok;
    try {
      ok = compiler.getTask(null, null, diagnostics, options, null, List.of(file)).call();
    } finally {
      // Only whether it compiles matters: the classes go.
      try (var made = Files.walk(out)) {
        for (Path p : made.sorted(java.util.Comparator.reverseOrder()).toList())
          Files.deleteIfExists(p);
      }
    }
    StringBuilder errors = new StringBuilder();
    for (Diagnostic<?> d : diagnostics.getDiagnostics())
      if (d.getKind() == Diagnostic.Kind.ERROR)
        errors
            .append(d.getLineNumber())
            .append(": ")
            .append(d.getMessage(Locale.ROOT))
            .append('\n');
    assertTrue(
        ok, doc + " example " + (index + 1) + " does not compile:\n" + errors + "\n" + source);
  }
}
