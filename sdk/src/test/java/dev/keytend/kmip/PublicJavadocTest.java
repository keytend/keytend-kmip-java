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

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The published Javadoc of the SDK and the in-memory server's sources (the keytend-kmip-testing
 * module, {@link #TESTING}). In {@code kms} and {@code testing} every published element is
 * documented (a type,
 * method, constructor, field, enum constant and record component, also nested and implicitly
 * public ones), every public top-level type says {@code @since}, and every deprecated element says
 * why in its {@code @deprecated} text, as {@code docs/compatibility.md} ("{@code @since} in the
 * Javadoc") promises; and javadoc's own doclint reports nothing for them.
 */
class PublicJavadocTest {
  static final Path MAIN = Path.of("src/main/java");

  /** The keytend-kmip-testing module's sources, whose classes the SDK's tests compile in. */
  static final Path TESTING = Path.of("../testing/src/main/java");

  /** The source roots these checks scan. */
  static final List<Path> ROOTS = List.of(MAIN, TESTING);

  /** {@code file} relative to the source root it is in. */
  static Path relative(Path file) {
    for (Path root : ROOTS) if (file.startsWith(root)) return root.relativize(file);
    return file;
  }

  // ---- every published element of kms and testing documented ----

  /** The packages whose every published element is documented, as source directories. */
  static final List<Path> COMPLETE =
      List.of(MAIN.resolve("dev/keytend/kmip/kms"), TESTING.resolve("dev/keytend/kmip/testing"));

  static final String MODIFIERS =
      "(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp|default|synchronized|native|transient|volatile)\\s+)*";
  static final Pattern TYPE =
      Pattern.compile("^" + MODIFIERS + "(class|interface|enum|record|@interface)\\s+(\\w+)");

  /**
   * One published element of a source file: its line, kind ({@code type}, {@code method}, {@code
   * field}, {@code constant}, {@code component}), name, Javadoc (null when it has none), whether it
   * is an {@code @Override} (inheriting its documentation), whether it is {@code @Deprecated}, and
   * whether it is a top-level type.
   */
  record Element(
      int line,
      String kind,
      String name,
      String doc,
      boolean override,
      boolean deprecated,
      boolean topLevel) {}

  /** A body being scanned: a type's (whose members are elements) or a block's (skipped). */
  private static final class Body {
    final boolean type, published, iface;
    boolean constants, skipToSemicolon;

    Body(boolean type, boolean published, boolean iface, boolean constants) {
      this.type = type;
      this.published = published;
      this.iface = iface;
      this.constants = constants;
    }
  }

  /** Whether the declaration {@code bare} has one of the modifiers {@code names} (a regex). */
  static boolean modifier(String bare, String names) {
    for (String word : bare.split(" ")) {
      if (word.matches(names)) return true;
      if (!word.matches(
          "public|protected|private|static|final|abstract|sealed|non-sealed|strictfp|default"))
        return false;
    }
    return false;
  }

  /** {@code source} with comments and literals blanked (newlines kept), and its Javadoc spans. */
  static String code(String source, List<int[]> docs) {
    char[] c = source.toCharArray();
    int n = c.length;
    for (int i = 0; i < n; ) {
      int end;
      if (source.startsWith("//", i))
        end = source.indexOf('\n', i) < 0 ? n : source.indexOf('\n', i);
      else if (source.startsWith("/*", i)) {
        end = source.indexOf("*/", i + 2) < 0 ? n : source.indexOf("*/", i + 2) + 2;
        if (source.startsWith("/**", i) && !source.startsWith("/**/", i))
          docs.add(new int[] {i, end});
      } else if (source.startsWith("\"\"\"", i))
        end = source.indexOf("\"\"\"", i + 3) < 0 ? n : source.indexOf("\"\"\"", i + 3) + 3;
      else if (c[i] == '"' || c[i] == '\'') {
        int j = i + 1;
        while (j < n && c[j] != c[i]) j += c[j] == '\\' ? 2 : 1;
        end = Math.min(n, j + 1);
      } else {
        i++;
        continue;
      }
      for (int k = i; k < end; k++) if (c[k] != '\n') c[k] = ' ';
      i = end;
    }
    return new String(c);
  }

  /** {@code head} without its annotations ({@code @Name} and its arguments), and the names removed. */
  static String withoutAnnotations(String head, Set<String> names) {
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < head.length(); ) {
      Matcher a =
          Pattern.compile("@(?!interface\\b)([\\w.]+)\\s*").matcher(head).region(i, head.length());
      if (head.charAt(i) != '@' || !a.lookingAt()) {
        out.append(head.charAt(i++));
        continue;
      }
      names.add(a.group(1));
      i = a.end();
      if (i < head.length() && head.charAt(i) == '(')
        for (int depth = 0; i < head.length(); i++) {
          if (head.charAt(i) == '(') depth++;
          else if (head.charAt(i) == ')' && --depth == 0) {
            i++;
            break;
          }
        }
      out.append(' ');
    }
    return out.toString().strip();
  }

  /**
   * The published elements of a Java source: top-level types that are public, and in a published
   * type its public or protected members, every member of an interface that is not private, its
   * enum constants and its record components. Comments and literals are blanked first, so braces
   * in them do not count; method bodies, initializers and enum constant bodies are skipped.
   */
  static List<Element> elements(String source) {
    List<int[]> docs = new ArrayList<>();
    String code = code(source, docs);
    List<Element> out = new ArrayList<>();
    Deque<Body> stack = new ArrayDeque<>();
    stack.push(new Body(true, true, false, false)); // the file: its members are top-level types
    int head = 0, paren = 0;
    for (int i = 0; i < code.length(); i++) {
      char c = code.charAt(i);
      Body body = stack.peek();
      if (!body.type) {
        if (c == '{') stack.push(new Body(false, false, false, false));
        else if (c == '}') {
          stack.pop();
          head = i + 1;
        }
        continue;
      }
      if (c == '(') paren++;
      else if (c == ')') paren--;
      if (paren > 0) continue;
      if (body.skipToSemicolon) {
        if (c == '{') stack.push(new Body(false, false, false, false));
        else if (c == ';') {
          body.skipToSemicolon = false;
          head = i + 1;
        }
        continue;
      }
      if (c != '{' && c != ';' && c != '}' && !(c == ',' && body.constants)) continue;
      String text = code.substring(head, i);
      Set<String> annotations = new HashSet<>();
      String bare = withoutAnnotations(text, annotations).replaceAll("\\s+", " ");
      int start = head + text.length() - text.stripLeading().length();
      int line = 1 + (int) code.substring(0, start).chars().filter(x -> x == '\n').count();
      String doc = null;
      for (int[] d : docs) if (d[0] >= head && d[1] <= i) doc = source.substring(d[0], d[1]);
      boolean top = stack.size() == 1;
      boolean published =
          body.published
              && (top
                  ? modifier(bare, "public")
                  : modifier(bare, "public|protected")
                      || (body.iface && !modifier(bare, "private")));
      boolean override = annotations.contains("Override"),
          deprecated = annotations.contains("Deprecated");
      Matcher type = TYPE.matcher(bare);
      if (body.constants && !bare.isEmpty() && !type.find()) {
        // an enum constant: NAME, NAME(arguments) or NAME { body }
        Matcher name = Pattern.compile("^(\\w+)").matcher(bare);
        if (body.published && name.find())
          out.add(new Element(line, "constant", name.group(1), doc, false, deprecated, false));
        if (c == '{') stack.push(new Body(false, false, false, false));
        else if (c == ';') body.constants = false;
        else if (c == '}') stack.pop();
      } else if (bare.isEmpty() || bare.equals("static")) {
        if (c == ';') body.constants = false;
        if (c == '{') stack.push(new Body(false, false, false, false));
        else if (c == '}') stack.pop();
      } else if (c == '{' && TYPE.matcher(bare).find()) {
        type = TYPE.matcher(bare);
        type.find();
        String kind = type.group(1);
        if (published) {
          out.add(new Element(line, "type", type.group(2), doc, false, deprecated, top));
          if (kind.equals("record")) {
            int open = text.indexOf('(', text.indexOf(type.group(2)));
            int close = open;
            for (int depth = 0; close < text.length(); close++)
              if (text.charAt(close) == '(') depth++;
              else if (text.charAt(close) == ')' && --depth == 0) break;
            String components =
                withoutAnnotations(text.substring(open + 1, close), new HashSet<>());
            while (!components.equals(components = components.replaceAll("<[^<>]*>", ""))) {}
            for (String p : components.split(","))
              if (!p.isBlank()) {
                String[] words = p.strip().split("\\s+");
                out.add(
                    new Element(
                        line, "component", words[words.length - 1], doc, false, false, false));
              }
          }
        }
        stack.push(
            new Body(
                true,
                published,
                kind.equals("interface") || kind.equals("@interface"),
                kind.equals("enum")));
      } else if (c == '}') {
        stack.pop();
      } else {
        int eq = bare.indexOf('='), call = bare.indexOf('(');
        // a compact constructor ("public R {") has neither
        boolean field = (call < 0 && (c != '{' || eq >= 0)) || (eq >= 0 && eq < call);
        String before =
            field
                ? bare.substring(0, eq < 0 ? bare.length() : eq)
                : call < 0 ? bare : bare.substring(0, call);
        String[] words = before.strip().split("[\\s,]+");
        String name = words[words.length - 1];
        if (published)
          out.add(
              new Element(
                  line, field ? "field" : "method", name, doc, override, deprecated, false));
        if (c == '{') {
          stack.push(new Body(false, false, false, false));
          if (field) body.skipToSemicolon = true;
        }
      }
      head = i + 1;
    }
    return out;
  }

  /** What {@link #elements} finds missing in {@code source}, as "line kind name: problem". */
  static List<String> undocumented(String source) {
    List<String> out = new ArrayList<>();
    String typeDoc = null;
    for (Element e : elements(source)) {
      if (e.kind().equals("type")) typeDoc = e.doc();
      String at = e.line() + " " + e.kind() + " " + e.name() + ": ";
      if (e.kind().equals("component")) {
        if (typeDoc == null
            || !Pattern.compile("@param\\s+" + e.name() + "\\s+\\S").matcher(typeDoc).find())
          out.add(at + "no @param on the record");
        continue;
      }
      if (e.doc() == null) {
        if (!e.override() || e.deprecated()) out.add(at + "no Javadoc");
        continue;
      }
      if (e.topLevel() && !e.doc().contains("@since")) out.add(at + "no @since");
      if (e.deprecated() && !Pattern.compile("@deprecated[\\s*]+[^\\s*/]").matcher(e.doc()).find())
        out.add(at + "no @deprecated text");
    }
    return out;
  }

  /**
   * Every published element of {@code kms} and {@code testing} has a Javadoc comment, or overrides
   * a documented method; every record component has an {@code @param}; every public top-level type
   * says {@code @since}; every {@code @Deprecated} element says why in {@code @deprecated}. The
   * scan is checked against the compiled classes: every public or protected type, method,
   * constructor and field that reflection finds ({@link PublicSurfaceTest#surface}'s elements) is
   * one the scan found too, by name, so a declaration the scan cannot read fails here rather than
   * pass unchecked.
   */
  @Test
  void everyPublishedElementOfKmsAndTestingIsDocumented() throws Exception {
    List<String> missing = new ArrayList<>(), unscanned = new ArrayList<>();
    int elements = 0;
    for (Path dir : COMPLETE) {
      assertTrue(Files.exists(dir.resolve("package-info.java")), dir + ": package-info.java");
      try (Stream<Path> files = Files.list(dir)) {
        for (Path f : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
          if (f.endsWith("package-info.java")) continue;
          String source = Files.readString(f);
          List<Element> found = elements(source);
          elements += found.size();
          for (String m : undocumented(source)) missing.add(relative(f) + ":" + m);
          String name = relative(f).toString().replace(f.getFileSystem().getSeparator(), ".");
          for (String m :
              unscanned(Class.forName(name.substring(0, name.length() - ".java".length())), found))
            unscanned.add(relative(f) + ": " + m);
        }
      }
    }
    assertEquals(List.of(), unscanned, "published elements the scan did not find");
    assertEquals(List.of(), missing, "undocumented elements");
    assertTrue(elements > 800, "the scan finds the elements: " + elements);
  }

  /**
   * The published elements of {@code top} and its nested types, by reflection, whose names the scan
   * of its source did not find. Left out: what the source does not declare (an enum's {@code
   * values} and {@code valueOf}, a record's implicit accessors and canonical constructor, which its
   * {@code @param}s document, and its {@code equals}, {@code hashCode} and {@code toString}).
   */
  static List<String> unscanned(Class<?> top, List<Element> found) {
    Set<String> names = new HashSet<>();
    for (Element e : found) names.add(e.name());
    List<String> out = new ArrayList<>();
    Deque<Class<?>> classes = new ArrayDeque<>(List.of(top));
    while (!classes.isEmpty()) {
      Class<?> c = classes.pop();
      classes.addAll(List.of(c.getDeclaredClasses()));
      if (!PublicSurfaceTest.visible(c)) continue;
      Set<String> components = new HashSet<>();
      if (c.isRecord()) for (var r : c.getRecordComponents()) components.add(r.getName());
      List<String> expected = new ArrayList<>(List.of(c.getSimpleName()));
      for (var k : c.getDeclaredConstructors())
        if (PublicSurfaceTest.published(k)
            && !(c.isRecord() && k.getParameterCount() == components.size()))
          expected.add(c.getSimpleName());
      for (var m : c.getDeclaredMethods())
        if (PublicSurfaceTest.published(m)
            && !m.isBridge()
            && !(c.isEnum() && (m.getName().equals("values") || m.getName().equals("valueOf")))
            && !(c.isRecord()
                && ((m.getParameterCount() == 0 && components.contains(m.getName()))
                    || m.getName().matches("equals|hashCode|toString")))) expected.add(m.getName());
      for (var f : c.getDeclaredFields())
        if (PublicSurfaceTest.published(f)) expected.add(f.getName());
      for (String n : expected) if (!names.contains(n)) out.add(c.getName() + "#" + n);
    }
    return out;
  }

  /** The member scan finds what it is for, in the shapes the sources use, and nothing else. */
  @Test
  void theMemberScanFindsUndocumentedElements() {
    String source =
        "package x;\n"
            + "/** A type without since. */\n"
            + "public final class X implements Runnable {\n"
            + "  /** Documented. */\n  public static final int A = 1;\n"
            + "  public static final Comparator<String> B = (a, b) -> { return 0; };\n"
            + "  private static final int[] C = {1, 2};\n"
            + "  /** Documented, with \"}\" and '{' in its text. */\n  public void d(String s) { if (s.equals(\"}\")) { } }\n"
            + "  public X(int e) { this(); }\n"
            + "  @Override\n  public void run() {}\n"
            + "  @SuppressWarnings({\"unchecked\"})\n  protected <T extends Comparable<T>> T f(List<T> l) { return null; }\n"
            + "  void packagePrivate() {}\n"
            + "  /** Deprecated without text.\n   *\n   * @deprecated\n   */\n  @Deprecated(since = \"0.10.0\")\n  public void g() {}\n"
            + "  /** A nested enum. */\n  public enum H {\n    /** Documented. */\n    H1(new Object() { public String toString() { return \"{\"; } }),\n    H2 { },\n    H3;\n"
            + "    public int i() { return 0; }\n  }\n"
            + "  /** A record. @param j documented */\n  public record J(int j, List<Map<String, Integer>> k) {\n    public J {}\n  }\n"
            + "  /** An interface. */\n  public interface L {\n    void m();\n    private void n() {}\n    /** Documented. */\n    default void o() {}\n    class P {}\n  }\n"
            + "  private static final class Q {\n    public void r() {}\n  }\n"
            + "}\n";
    assertEquals(
        List.of(
            "3 type X: no @since",
            "6 field B: no Javadoc",
            "10 method X: no Javadoc",
            "13 method f: no Javadoc",
            "20 method g: no @deprecated text",
            "26 constant H2: no Javadoc",
            "27 constant H3: no Javadoc",
            "28 method i: no Javadoc",
            "31 component k: no @param on the record",
            "32 method J: no Javadoc",
            "36 method m: no Javadoc",
            "40 type P: no Javadoc"),
        undocumented(source));
    assertEquals(
        List.of(),
        undocumented(
            "package x;\n/** Package-private. */\nfinal class Y {\n  public void a() {}\n}\n"));
  }

  /**
   * Where the modules the SDK requires, outside the JDK, are (slf4j-api's JAR, say): as this test
   * run resolved them.
   */
  static String dependencyModulePath() {
    java.util.StringJoiner path = new java.util.StringJoiner(java.io.File.pathSeparator);
    for (java.lang.module.ModuleDescriptor.Requires r :
        PublicJavadocTest.class.getModule().getDescriptor().requires()) {
      if (r.name().startsWith("java.") || r.name().startsWith("jdk.")) continue;
      ModuleLayer.boot()
          .configuration()
          .findModule(r.name())
          .flatMap(m -> m.reference().location())
          .ifPresent(location -> path.add(Path.of(location).toString()));
    }
    return path.toString();
  }

  /**
   * Javadoc's own doclint ({@code -Xdoclint:all}) reports nothing for {@code kms}: no missing
   * {@code @param}, {@code @return} or {@code @throws}, no missing comment, no broken {@code
   * {@link}}, no HTML error. Doclint is restricted to that package ({@code -Xdoclint/package}): the
   * protocol packages leave members without a comment. The build's own doclint execution ({@code
   * sdk/pom.xml}) checks every other group in every package; {@code testing/pom.xml}'s checks every
   * group, "missing" included, in the testing module. Runs the
   * JDK's {@code javadoc} on the module's sources, writing to a temporary directory, in a few
   * seconds.
   */
  @Test
  void javadocReportsNothingForKms() throws Exception {
    Path javadoc = Path.of(System.getProperty("java.home"), "bin", "javadoc");
    if (!Files.isExecutable(javadoc)) javadoc = javadoc.resolveSibling("javadoc.exe");
    assertTrue(Files.isExecutable(javadoc), "the tests run on a JDK with javadoc: " + javadoc);
    Path out = Files.createTempDirectory("keytend-doclint");
    try {
      Process p =
          new ProcessBuilder(
                  javadoc.toString(),
                  "-quiet",
                  "-d",
                  out.toString(),
                  "--source-path",
                  MAIN.toAbsolutePath().toString(),
                  "--module-path",
                  dependencyModulePath(),
                  "--module",
                  "dev.keytend.kmip",
                  "-Xdoclint:all",
                  "-Xdoclint/package:dev.keytend.kmip.kms",
                  "-Xmaxwarns",
                  "10000",
                  "-Xmaxerrs",
                  "10000")
              .redirectErrorStream(true)
              .start();
      String log = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      int exit = p.waitFor();
      List<String> reported =
          log.lines().filter(l -> l.matches(".*: (warning|error)[: ].*")).toList();
      assertEquals(List.of(), reported, "javadoc reports, for kms");
      assertEquals(0, exit, log);
    } finally {
      try (Stream<Path> files = Files.walk(out)) {
        for (Path f : files.sorted(Comparator.reverseOrder()).toList()) Files.delete(f);
      }
    }
  }
}
