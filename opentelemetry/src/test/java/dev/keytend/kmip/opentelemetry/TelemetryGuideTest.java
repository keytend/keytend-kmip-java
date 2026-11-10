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
package dev.keytend.kmip.opentelemetry;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import io.opentelemetry.sdk.metrics.data.MetricData;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.function.BiConsumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;

/**
 * The {@code java} blocks of docs/production.md's "OpenTelemetry" section compile against this
 * module, the SDK and the OpenTelemetry API, and the one that connects with the {@code config} of
 * the block before runs, against an in-memory server with the key it needs, its instruments read
 * through the OpenTelemetry SDK. The SDK's DocSnippetsTest compiles the rest of the guide, and
 * leaves this section here, where OpenTelemetry is on the class path.
 */
class TelemetryGuideTest {
  static final String SECTION = "## OpenTelemetry";

  /** The section's {@code java} blocks. */
  static List<String> blocks() throws IOException {
    String text = Files.readString(Path.of("../docs/production.md"));
    int start = text.indexOf("\n" + SECTION + "\n");
    assertTrue(start >= 0, "docs/production.md has the section " + SECTION);
    int end = text.indexOf("\n## ", start + SECTION.length() + 1);
    String section = end < 0 ? text.substring(start) : text.substring(start, end);
    List<String> out = new ArrayList<>();
    Matcher m = Pattern.compile("```java\\n(.*?)```", Pattern.DOTALL).matcher(section);
    while (m.find()) out.add(m.group(1));
    return out;
  }

  /** The class path this test runs with, the module path's entries included. */
  static String classPath() {
    List<String> entries = new ArrayList<>();
    for (String property : List.of("jdk.module.path", "java.class.path")) {
      String value = System.getProperty(property, "");
      if (!value.isEmpty()) entries.add(value);
    }
    return String.join(File.pathSeparator, entries);
  }

  static final String IMPORTS =
      "import dev.keytend.kmip.kms.*;\n"
          + "import dev.keytend.kmip.opentelemetry.*;\n"
          + "import io.opentelemetry.api.OpenTelemetry;\n"
          + "import java.nio.file.Path;\n";

  @Test
  void theExamplesCompile() throws IOException {
    List<String> blocks = blocks();
    assertEquals(2, blocks.size(), "the configuration and the instruments");
    for (int i = 0; i < blocks.size(); i++) {
      StringBuilder body = new StringBuilder();
      for (String line : blocks.get(i).split("\n"))
        body.append(line.strip().equals("...") ? "// ..." : line).append('\n');
      String source =
          IMPORTS
              + "class Example {\n  OpenTelemetry openTelemetry;\n  KmsConfig config;\n"
              + "  KmipTelemetry telemetry;\n"
              + "  void run() throws Exception {\n"
              + body
              + "  }\n}\n";
      compile(i + 1, source, "Example");
    }
  }

  /**
   * The block that connects with {@code config} runs, with the listeners' configuration on an
   * in-memory server that has the key it opens: its builder calls are all a cache needs, and its
   * instruments report ({@code ...} checks them) until they are closed.
   */
  @Test
  void theInstrumentsExampleRuns() throws Exception {
    String block =
        blocks().stream()
            .filter(b -> b.contains("Kms.connect(config)") && !b.contains("KmsConfig config ="))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no example connects with config"));
    StringBuilder body = new StringBuilder();
    for (String line : block.split("\n"))
      body.append(line.strip().equals("...") ? "probe.run();" : line).append('\n');
    String source =
        IMPORTS
            + "public class RunExample implements java.util.function.BiConsumer<KmsConfig,"
            + " KmipTelemetry> {\n"
            + "  public static Runnable probe = () -> {};\n"
            + "  public void accept(KmsConfig config, KmipTelemetry telemetry) {\n"
            + "    try {\n"
            + body
            + "    } catch (Exception e) {\n      throw new RuntimeException(e);\n    }\n  }\n}\n";
    Path out = compile(0, source, "RunExample");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = server.connect()) {
      kms.keys()
          .createAes(256)
          .named("orders-kek")
          .extractable(true)
          .custom(CustomAttribute.client("family"), "orders")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .create();
    }
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      KmsConfig config =
          server
              .configure()
              .addListener(telemetry.metricsListener())
              .addListener(telemetry.tracingListener())
              .build();
      boolean[] probed = {false};
      try (URLClassLoader loader =
          new URLClassLoader(
              new URL[] {out.toUri().toURL()}, TelemetryGuideTest.class.getClassLoader())) {
        Class<?> example = loader.loadClass("RunExample");
        example
            .getField("probe")
            .set(
                null,
                (Runnable)
                    () -> {
                      assertEquals(
                          0,
                          otel.longValue(
                              "kmip.localkeys.load.failures",
                              Otel.attrs("kmip.localkeys.name", "orders-kek")));
                      probed[0] = true;
                    });
        Object instance = example.getConstructor().newInstance();
        @SuppressWarnings("unchecked")
        BiConsumer<KmsConfig, KmipTelemetry> accept =
            (BiConsumer<KmsConfig, KmipTelemetry>) instance;
        accept.accept(config, telemetry);
      }
      assertTrue(probed[0], "the example reached its body");
      Collection<MetricData> after = otel.collect();
      assertTrue(
          Otel.metric(after, "kmip.localkeys.entry.count").stream()
              .allMatch(m -> Otel.points(m).isEmpty()),
          "the instruments' close removed them");
    }
  }

  private static Path compile(int number, String source, String name) throws IOException {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "tests need a JDK");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    JavaFileObject file =
        new SimpleJavaFileObject(
            URI.create("string:///" + name + ".java"), JavaFileObject.Kind.SOURCE) {
          @Override
          public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return source;
          }
        };
    Path out = Files.createTempDirectory("telemetry-guide");
    List<String> options =
        List.of(
            "-classpath",
            classPath(),
            "-d",
            out.toString(),
            "-proc:none",
            "--release",
            "17",
            "-Xlint:-options");
    boolean ok = compiler.getTask(null, null, diagnostics, options, null, List.of(file)).call();
    StringBuilder errors = new StringBuilder();
    for (Diagnostic<?> d : diagnostics.getDiagnostics())
      if (d.getKind() == Diagnostic.Kind.ERROR)
        errors
            .append(d.getLineNumber())
            .append(": ")
            .append(d.getMessage(Locale.ROOT))
            .append('\n');
    assertTrue(
        ok, "OpenTelemetry example " + number + " does not compile:\n" + errors + "\n" + source);
    return out;
  }
}
