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

import java.io.IOException;
import java.io.InputStream;
import java.lang.module.ModuleDescriptor;
import java.lang.reflect.*;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;
import java.util.regex.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * What becomes API is chosen, not accidental. The public surface of every package (public
 * and protected types and members, as japicmp and {@code docs/compatibility.md} count them) is
 * compared with the last release's, listed in {@code src/test/resources/api/X.Y.Z.txt}, which
 * {@link #main} writes from the released JAR:
 *
 * <pre>
 * java -cp sdk/target/test-classes:sdk/target/classes dev.keytend.kmip.PublicSurfaceTest \
 *     keytend-kmip-X.Y.Z/lib/keytend-kmip-X.Y.Z.jar keytend-kmip-X.Y.Z/lib/slf4j-api-*.jar \
 *     &gt; sdk/src/test/resources/api/X.Y.Z.txt
 * </pre>
 *
 * A release adds its own list to {@link #RELEASES} when it becomes the API baseline
 * (docs/releasing.md); a list is never regenerated. keytend-kmip's API history starts at its
 * first release, 0.10.0, whose list will be the first: until it is published there is none, and
 * every element is new.
 */
class PublicSurfaceTest {
  static final Path MAIN = Path.of("src/main/java");

  /**
   * The keytend-kmip-testing module's sources (the in-memory server), whose classes the SDK's tests
   * compile in. Outside the SDK's surface and its compatibility lists (docs/compatibility.md, "The
   * testing package"), but held to the same rules for what is published: nothing deprecated, no
   * mutable field, only the reviewed null-ambiguous overloads, {@code @since} a keytend version.
   */
  static final Path TESTING = Path.of("../testing/src/main/java");

  /**
   * The keytend-kmip releases whose surface lists are in {@code src/test/resources/api/}, oldest
   * first, each added when it becomes the API baseline (docs/releasing.md).
   */
  static final List<String> RELEASES = List.of();

  // ---- the surface, as one line per element ----

  /** Whether {@code c} can be named from outside its package: public, nested in public types. */
  static boolean visible(Class<?> c) {
    if (c.isAnonymousClass() || c.isLocalClass() || c.isSynthetic()) return false;
    for (Class<?> x = c; x != null; x = x.getDeclaringClass()) {
      int m = x.getModifiers();
      if (!(Modifier.isPublic(m) || (x.getDeclaringClass() != null && Modifier.isProtected(m))))
        return false;
    }
    return true;
  }

  static boolean published(Member m) {
    return !m.isSynthetic()
        && (Modifier.isPublic(m.getModifiers()) || Modifier.isProtected(m.getModifiers()));
  }

  static String params(Class<?>[] types) {
    StringJoiner j = new StringJoiner(",", "(", ")");
    for (Class<?> t : types) j.add(t.getTypeName());
    return j.toString();
  }

  /**
   * The published elements of {@code types}: {@code T name}, {@code C name#<init>(params)}, {@code
   * M name#method(params)} and {@code F name#field}, sorted.
   */
  static SortedSet<String> surface(Collection<Class<?>> types) {
    SortedSet<String> out = new TreeSet<>();
    for (Class<?> c : types) {
      if (!visible(c)) continue;
      String n = c.getName();
      out.add("T " + n);
      for (Constructor<?> k : c.getDeclaredConstructors())
        if (published(k)) out.add("C " + n + "#<init>" + params(k.getParameterTypes()));
      for (Method m : c.getDeclaredMethods())
        if (published(m) && !m.isBridge())
          out.add("M " + n + "#" + m.getName() + params(m.getParameterTypes()));
      for (Field f : c.getDeclaredFields()) if (published(f)) out.add("F " + n + "#" + f.getName());
    }
    return out;
  }

  /** Every class in the JAR or class directory {@code root}, loaded (not initialized) by {@code loader}. */
  static List<Class<?>> classes(List<String> names, ClassLoader loader)
      throws ClassNotFoundException {
    List<Class<?>> out = new ArrayList<>();
    for (String name : names) out.add(Class.forName(name, false, loader));
    return out;
  }

  static boolean isClass(String entry) {
    return entry.endsWith(".class")
        && !entry.endsWith("module-info.class")
        && !entry.endsWith("package-info.class");
  }

  static String className(String entry) {
    return entry.substring(0, entry.length() - ".class".length()).replace('/', '.');
  }

  /** This SDK's classes: every type its sources declare, nested ones included. */
  static List<Class<?>> current() throws IOException, ClassNotFoundException {
    return declared(MAIN);
  }

  /** The SDK's classes and the testing module's ({@link #TESTING}). */
  static List<Class<?>> currentAndTesting() throws IOException, ClassNotFoundException {
    List<Class<?>> out = new ArrayList<>(current());
    out.addAll(declared(TESTING));
    return out;
  }

  /** Every type the sources under {@code root} declare, nested ones included. */
  static List<Class<?>> declared(Path root) throws IOException, ClassNotFoundException {
    List<Class<?>> out = new ArrayList<>();
    try (Stream<Path> files = Files.walk(root)) {
      for (Path f : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
        String file = f.getFileName().toString();
        if (file.equals("package-info.java") || file.equals("module-info.java")) continue;
        String name = root.relativize(f).toString().replace(f.getFileSystem().getSeparator(), ".");
        nested(Class.forName(name.substring(0, name.length() - ".java".length())), out);
      }
    }
    return out;
  }

  private static void nested(Class<?> c, List<Class<?>> out) {
    out.add(c);
    for (Class<?> d : c.getDeclaredClasses()) nested(d, out);
  }

  /**
   * The release this tree builds: the project's {@code <version>} (the next release, X.Y.Z), or the
   * release a pre-release X.Y.Z-rc.N is of.
   */
  static String version() throws IOException {
    Matcher m =
        Pattern.compile(
                "<artifactId>keytend-kmip-parent</artifactId>\\s*<version>([^<]+)</version>")
            .matcher(Files.readString(Path.of("../pom.xml")));
    assertTrue(m.find(), "the project version in pom.xml");
    return release(m.group(1).strip());
  }

  /**
   * A release version, X.Y.Z or a pre-release X.Y.Z-rc.N with N from 1, as the release tools take
   * it (tools/package-release.py, VERSION_PATTERN).
   */
  static final Pattern RELEASE_VERSION =
      Pattern.compile("(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(-rc\\.[1-9]\\d*)?");

  /** The release {@code version} is of: X.Y.Z itself, or the X.Y.Z of X.Y.Z-rc.N. */
  static String release(String version) {
    assertTrue(
        RELEASE_VERSION.matcher(version).matches(), "X.Y.Z or X.Y.Z-rc.N (N >= 1): " + version);
    return version.replaceFirst("-rc\\.[1-9]\\d*$", "");
  }

  /** The version rule is the release tools': no -rc.0, no leading zeros, three parts. */
  @Test
  void theReleaseVersionIsTheToolsOne() throws IOException {
    assertEquals("0.10.0", release("0.10.0-rc.1"));
    assertEquals("0.10.0", release("0.10.0-rc.12"));
    assertEquals("1.2.3", release("1.2.3"));
    for (String bad : List.of("0.10.0-rc.0", "0.10.0-rc.01", "0.10", "01.10.0", "0.10.0-beta.1"))
      assertThrows(AssertionError.class, () -> release(bad), bad);
    String tools = Files.readString(Path.of("../tools/package-release.py"));
    assertTrue(
        tools.contains("VERSION_PATTERN = r'" + RELEASE_VERSION.pattern() + "'"),
        "package-release.py's VERSION_PATTERN is " + RELEASE_VERSION.pattern());
  }

  /** The last release's surface: its list; none before the first release's list exists. */
  static Optional<Set<String>> released() throws IOException {
    if (!RELEASES.isEmpty())
      return Optional.of(list("/api/" + RELEASES.get(RELEASES.size() - 1) + ".txt"));
    return Optional.empty();
  }

  /**
   * A release's surface list, {@code /api/X.Y.Z.txt}, without the testing package: the in-memory
   * server is no longer in the SDK (it is the keytend-kmip-testing module, outside the
   * compatibility guarantee), and a list written from a JAR that still had it keeps its lines.
   */
  static Set<String> list(String resource) throws IOException {
    try (InputStream in = PublicSurfaceTest.class.getResourceAsStream(resource)) {
      assertNotNull(in, resource);
      return new TreeSet<>(
          new String(in.readAllBytes(), StandardCharsets.UTF_8)
              .lines()
              .filter(l -> !l.matches("[TCMF] dev\\.keytend\\.kmip\\.testing\\..*"))
              .toList());
    }
  }

  /**
   * Writes the surface of the JAR {@code args[0]} (the baseline lists), one element per line. The
   * other arguments are the JARs it needs at run time (slf4j-api), which are on the loader's path
   * but not listed. Only the packages its module descriptor exports are listed: the SDK JAR also
   * holds Caffeine, relocated under {@code dev.keytend.kmip.internal.shaded}, which is not API.
   */
  public static void main(String[] args) throws Exception {
    URL[] path = new URL[args.length];
    for (int i = 0; i < args.length; i++) path[i] = Path.of(args[i]).toUri().toURL();
    try (JarFile jar = new JarFile(args[0]);
        URLClassLoader loader = new URLClassLoader(path, ClassLoader.getPlatformClassLoader())) {
      var descriptor = jar.getEntry("module-info.class");
      if (descriptor == null)
        throw new IllegalArgumentException(args[0] + ": no module-info.class");
      Set<String> exported = new HashSet<>();
      try (InputStream in = jar.getInputStream(descriptor)) {
        for (ModuleDescriptor.Exports e : ModuleDescriptor.read(in).exports())
          exported.add(e.source());
      }
      List<String> names =
          jar.stream()
              .map(e -> e.getName())
              .filter(PublicSurfaceTest::isClass)
              .map(PublicSurfaceTest::className)
              .filter(n -> exported.contains(n.substring(0, n.lastIndexOf('.'))))
              .sorted()
              .toList();
      for (String line : surface(classes(names, loader))) System.out.println(line);
    }
  }

  // ---- the module ----

  /** The packages with public API, as docs/compatibility.md lists them ("Java"). */
  static final Set<String> EXPORTED =
      Set.of("kms", "client", "model", "codec", "transport", "server").stream()
          .map(p -> "dev.keytend.kmip." + p)
          .collect(java.util.stream.Collectors.toUnmodifiableSet());

  /**
   * The SDK is the named module {@code dev.keytend.kmip} (src/main/java/module-info.java),
   * and these tests run in it, as Surefire patches them in: a build that put the SDK on the class
   * path instead would fail here. The descriptor exports every package with public API, unqualified,
   * opens none, and requires only {@code java.base}, {@code java.net.http}, {@code java.xml},
   * {@code org.slf4j} (logging, docs/dependencies.md) and {@code com.github.benmanes.caffeine},
   * none transitively (no type of theirs is in the API). Caffeine is required here, by the source
   * descriptor the tests run in; the published JAR bundles it relocated and its descriptor does not
   * require it (ModularConsumerIT in integration-tests checks that one). Every package of the
   * main sources is
   * exported; only the SDK's tables (resources in {@code dev.keytend.kmip}, not a source package)
   * are not.
   */
  @Test
  void theModuleExportsEveryPackageWithPublicApi() throws IOException {
    Module module = dev.keytend.kmip.kms.Kms.class.getModule();
    assertTrue(module.isNamed(), "the SDK runs as a named module");
    assertEquals(module, PublicSurfaceTest.class.getModule(), "the tests are patched into it");
    ModuleDescriptor d = module.getDescriptor();
    assertEquals("dev.keytend.kmip", d.name());
    assertFalse(d.isAutomatic() || d.isOpen());
    Set<String> exported = new TreeSet<>();
    for (ModuleDescriptor.Exports e : d.exports()) {
      assertFalse(e.isQualified(), e.toString());
      exported.add(e.source());
    }
    assertEquals(new TreeSet<>(EXPORTED), exported);
    assertEquals(Set.of(), d.opens());
    Map<String, Set<ModuleDescriptor.Requires.Modifier>> requires = new TreeMap<>();
    for (ModuleDescriptor.Requires r : d.requires()) requires.put(r.name(), r.modifiers());
    assertEquals(
        Set.of(
            "java.base", "java.net.http", "java.xml", "org.slf4j", "com.github.benmanes.caffeine"),
        requires.keySet());
    assertEquals(Set.of(), requires.get("java.net.http"));
    assertEquals(Set.of(), requires.get("java.xml"));
    assertEquals(Set.of(), requires.get("org.slf4j"));
    assertEquals(Set.of(), requires.get("com.github.benmanes.caffeine"));
    Set<String> sourcePackages = new TreeSet<>();
    try (Stream<Path> files = Files.walk(MAIN)) {
      for (Path f :
          files
              .filter(p -> p.toString().endsWith(".java") && !p.endsWith("module-info.java"))
              .toList())
        sourcePackages.add(
            MAIN.relativize(f.getParent())
                .toString()
                .replace(f.getFileSystem().getSeparator(), "."));
    }
    assertEquals(
        new TreeSet<>(EXPORTED), sourcePackages, "every package of the sources is exported");
    String page = Files.readString(Path.of("../docs/compatibility.md")).replaceAll("\\s+", " ");
    assertTrue(
        page.contains("The JAR is the named module `dev.keytend.kmip`"),
        "docs/compatibility.md names the module");
    for (String p : EXPORTED)
      assertTrue(
          page.contains("`" + p.substring("dev.keytend.kmip.".length()) + "`"),
          "docs/compatibility.md lists " + p);
    assertFalse(page.contains("There is no `module-info`"));
  }

  /**
   * The JAR's manifest has no {@code Automatic-Module-Name}: with a descriptor it would be ignored,
   * and a reader of the manifest would be told something the module system does not do.
   */
  @Test
  void theManifestHasNoAutomaticModuleName() throws IOException {
    String pom = Files.readString(Path.of("pom.xml"));
    assertFalse(pom.contains("<Automatic-Module-Name>"), "sdk/pom.xml");
    assertTrue(
        Files.readString(MAIN.resolve("module-info.java")).contains("module dev.keytend.kmip {"));
  }

  // ---- @since ----

  /**
   * Every element new since the last keytend-kmip release says {@code @since} the version this
   * tree builds: a new type in its own Javadoc (its members need not repeat it), a new member
   * of an older type in the member's. Before the first release, 0.10.0, is published every element
   * is new, so every type says {@code @since 0.10.0}. Overrides of {@code Object}'s methods and an enum's implicit methods are
   * left out.
   */
  @Test
  void everyElementNewSinceTheLastReleaseSaysTheVersionThisTreeBuilds() throws Exception {
    String version = version();
    Set<String> released = RELEASES.isEmpty() ? Set.of() : released().orElseThrow();
    List<String> added = surface(current()).stream().filter(l -> !released.contains(l)).toList();
    Set<String> newTypes = new HashSet<>();
    for (String l : added) if (l.startsWith("T ")) newTypes.add(l.substring(2));
    Pattern since = Pattern.compile("@since\\s+" + Pattern.quote(version) + "(?![\\w.])");
    List<String> wrong = new ArrayList<>();
    for (String l : added) {
      String owner = l.substring(2).split("#")[0];
      if (!l.startsWith("T ") && newTypes.contains(owner)) continue;
      // A nested type of a new type inherits its @since, as members do.
      if (l.startsWith("T ")
          && owner.contains("$")
          && newTypes.contains(owner.substring(0, owner.lastIndexOf('$')))) continue;
      String member = l.contains("#") ? l.substring(l.indexOf('#') + 1) : null;
      if (member != null
          && member.matches(
              "(toString|hashCode)\\(\\)|equals\\(java\\.lang\\.Object\\)|values\\(\\)|valueOf\\(java\\.lang\\.String\\)"))
        continue;
      Optional<String> doc = javadoc(l);
      if (doc.isEmpty()) wrong.add(l + ": no Javadoc found");
      else if (!since.matcher(doc.get()).find()) wrong.add(l);
    }
    if (RELEASES.isEmpty()) { // before the first release every element is new: not vacuous
      assertTrue(added.size() > 100, "elements new since the last release: " + added.size());
      assertTrue(newTypes.size() > 100, "types new since the last release: " + newTypes.size());
    }
    assertEquals(List.of(), wrong, "new since the last release without @since " + version);
  }

  /**
   * Every {@code @since} in the main sources names a keytend-kmip release ({@link #RELEASES}) or the
   * release this tree builds: no other value is left.
   */
  @Test
  void everySinceNamesAKeytendVersion() throws Exception {
    Set<String> allowed = new HashSet<>(RELEASES);
    allowed.add(version());
    Pattern since = Pattern.compile("@since\\s+(\\S+)");
    Set<String> found = new TreeSet<>();
    List<String> wrong = new ArrayList<>();
    for (Path root : List.of(MAIN, TESTING))
      try (Stream<Path> files = Files.walk(root)) {
        for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
          Matcher m = since.matcher(Files.readString(f));
          while (m.find()) {
            found.add(m.group(1));
            if (!allowed.contains(m.group(1)))
              wrong.add(root.relativize(f) + ": @since " + m.group(1));
          }
        }
      }
    assertFalse(found.isEmpty(), "the sources say @since");
    assertEquals(List.of(), wrong, "@since values other than " + allowed);
  }

  /** The surface lists are exactly those of {@link #RELEASES}. */
  @Test
  void theListsAreThoseOfTheReleases() throws IOException {
    Set<String> files = new TreeSet<>();
    Path api = Path.of("src/test/resources/api");
    if (Files.isDirectory(api)) {
      try (Stream<Path> list = Files.list(api)) {
        list.forEach(p -> files.add(p.getFileName().toString()));
      }
    }
    Set<String> expected = new TreeSet<>();
    for (String r : RELEASES) expected.add(r + ".txt");
    assertEquals(expected, files);
  }

  /** The scan finds a member's own Javadoc, matching overloads by their parameter types. */
  @Test
  void theSinceScanMatchesOverloads() {
    String source =
        "public final class X {\n  /** Old. */\n  public void a(java.nio.file.Path p, byte[] b) {}\n"
            + "  /**\n   * New.\n   *\n   * @since 0.10.0\n   */\n  @Deprecated\n  public void a(Path p, byte[] b, Mode m)\n      throws IOException {}\n"
            + "  /** Generic. @since 0.10.0 */\n  public <T> Supplier<T> b(Function<KeyHandle, ? extends T> f) { return null; }\n}\n";
    assertEquals(Optional.of("/** Old. */"), javadoc(source, "X", "a", List.of("Path", "byte[]")));
    assertTrue(
        javadoc(source, "X", "a", List.of("Path", "byte[]", "Mode"))
            .orElseThrow()
            .contains("@since 0.10.0"));
    assertTrue(javadoc(source, "X", "b", List.of("Function")).orElseThrow().contains("@since"));
    assertEquals(Optional.empty(), javadoc(source, "X", "a", List.of("Path")));
  }

  /** The Javadoc of the element {@code line} names, from its source. */
  static Optional<String> javadoc(String line) throws IOException, ClassNotFoundException {
    String rest = line.substring(2);
    String owner = rest.split("#")[0];
    String top = owner.contains("$") ? owner.substring(0, owner.indexOf('$')) : owner;
    String source = Files.readString(MAIN.resolve(top.replace('.', '/') + ".java"));
    String simple = owner.substring(Math.max(owner.lastIndexOf('.'), owner.lastIndexOf('$')) + 1);
    if (line.startsWith("T "))
      return before(
          source,
          Pattern.compile(
              "^\\s*(?:public|protected)\\s+(?:\\w+\\s+)*(?:class|interface|enum|record|@interface)\\s+"
                  + simple
                  + "\\b",
              Pattern.MULTILINE));
    String member = rest.substring(rest.indexOf('#') + 1);
    if (line.startsWith("F "))
      return before(
          source,
          Pattern.compile(
              "^\\s*(?:(?:public|protected|static|final)\\s+)*(?:[\\w.<>\\[\\]]+\\s+)?"
                  + member
                  // The last constant of an enum is followed by the enum's closing brace.
                  + "\\s*(?:[,;=(]|\\R\\s*})",
              Pattern.MULTILINE));
    String name = member.substring(0, member.indexOf('('));
    if (name.equals("<init>")) name = simple;
    Class<?> c = Class.forName(owner);
    List<String> want = new ArrayList<>();
    String list = member.substring(member.indexOf('(') + 1, member.length() - 1);
    for (String p : list.isEmpty() ? new String[0] : list.split(",")) want.add(simpleName(p));
    return javadoc(source, c.getSimpleName(), name, want);
  }

  static String simpleName(String typeName) {
    String t = typeName.replace("...", "[]");
    return t.substring(Math.max(t.lastIndexOf('.'), t.lastIndexOf('$')) + 1);
  }

  /**
   * The Javadoc before the declaration of method (or constructor) {@code name} in {@code source}
   * whose parameter types, by simple erased name, are {@code params}; a one-letter type variable
   * matches any type.
   */
  static Optional<String> javadoc(String source, String owner, String name, List<String> params) {
    Matcher m =
        Pattern.compile(
                "^[ \\t]*(?:(?:public|protected|private|static|final|abstract|default|synchronized|native)\\s+|<[^>]*>\\s+)*(?:[\\w.<>\\[\\]?, ]+\\s+)?"
                    + Pattern.quote(name)
                    + "\\s*\\(",
                Pattern.MULTILINE)
            .matcher(source);
    while (m.find()) {
      int open = m.end() - 1, depth = 0, close = open;
      for (int i = open; i < source.length(); i++) {
        char ch = source.charAt(i);
        if (ch == '(') depth++;
        else if (ch == ')' && --depth == 0) {
          close = i;
          break;
        }
      }
      List<String> declared = declaredTypes(source.substring(open + 1, close));
      if (declared == null || declared.size() != params.size()) continue;
      boolean same = true;
      for (int i = 0; i < params.size(); i++)
        if (!declared.get(i).equals(params.get(i)) && !declared.get(i).matches("[A-Z]"))
          same = false;
      if (!same) continue;
      Optional<String> doc =
          before(
              source.substring(0, m.end()),
              Pattern.compile(Pattern.quote(source.substring(m.start(), m.end())) + "\\z"));
      if (doc.isPresent()) return doc;
    }
    return Optional.empty();
  }

  /**
   * The simple erased type of each parameter in a declaration's parameter list; null when it is not
   * one (the arguments of a call).
   */
  static List<String> declaredTypes(String list) {
    String erased = list;
    for (String prior = null; !erased.equals(prior); ) {
      prior = erased;
      erased = erased.replaceAll("<[^<>]*>", "");
    }
    List<String> out = new ArrayList<>();
    for (String p : erased.split(",")) {
      String t = p.replaceAll("@\\w+(\\([^)]*\\))?", "").replace("final ", "").strip();
      if (t.isEmpty()) continue;
      if (t.lastIndexOf(' ') < 0 || !t.matches("[\\w.\\[\\] ]+\\s\\w+")) return null;
      t = t.substring(0, t.lastIndexOf(' ')).strip().replace(" ", "");
      out.add(simpleName(t));
    }
    return out;
  }

  /** The Javadoc comment right before the first match of {@code declaration}, past annotations. */
  static Optional<String> before(String source, Pattern declaration) {
    Matcher d = declaration.matcher(source);
    if (!d.find()) return Optional.empty();
    String text = source.substring(0, d.start()).stripTrailing();
    while (true) {
      Matcher a = Pattern.compile("@\\w+(?:\\([^)]*\\))?$").matcher(text);
      if (text.endsWith("*/") || !a.find()) break;
      text = text.substring(0, a.start()).stripTrailing();
    }
    if (!text.endsWith("*/")) return Optional.empty();
    return Optional.of(text.substring(text.lastIndexOf("/**")));
  }

  /**
   * No public or protected constructor is new since the last release: new types are made by
   * factories and builders, so that a type can change how it is made without breaking callers. A
   * justified one goes on this test's list, with its reason. Before the first release's list
   * exists there is nothing to compare with.
   */
  @Test
  void noPublicConstructorIsNewSinceTheLastRelease() throws Exception {
    Optional<Set<String>> last = released();
    org.junit.jupiter.api.Assumptions.assumeTrue(last.isPresent(), "no earlier release's surface");
    Set<String> released = last.get();
    assertEquals(
        List.of(),
        surface(current()).stream()
            .filter(l -> l.startsWith("C ") && !released.contains(l) && !JUSTIFIED.containsKey(l))
            .toList());
  }

  /** The public constructors added on purpose, each with its reason. */
  static final Map<String, String> JUSTIFIED =
      Map.of(
          "C dev.keytend.kmip.kms.StateConflictException#<init>(java.lang.String,"
              + "dev.keytend.kmip.kms.StateConflictException$Conflict)",
          "an exception application code throws in tests of a handler that switches on"
              + " conflict(), as KeyMismatchException(String, Category) is for category()");

  /**
   * Nothing published is deprecated: the first release, 0.10.0, starts with no deprecated element,
   * and a new deprecation is a conscious decision. The scan covers the annotation on published
   * types and members and the Javadoc tag in the main sources. A deprecation a later release makes
   * (docs/compatibility.md) is added to {@code allowed} with it.
   */
  @Test
  void nothingPublishedIsDeprecated() throws Exception {
    final Set<String> allowed = Set.of();
    List<String> deprecated = new ArrayList<>();
    for (Class<?> c : currentAndTesting()) {
      if (!visible(c)) continue;
      if (c.isAnnotationPresent(Deprecated.class)) deprecated.add("T " + c.getName());
      for (Constructor<?> k : c.getDeclaredConstructors())
        if (published(k) && k.isAnnotationPresent(Deprecated.class))
          deprecated.add("C " + c.getName() + "#<init>" + params(k.getParameterTypes()));
      for (Method m : c.getDeclaredMethods())
        if (published(m) && m.isAnnotationPresent(Deprecated.class))
          deprecated.add("M " + c.getName() + "#" + m.getName() + params(m.getParameterTypes()));
      for (Field f : c.getDeclaredFields())
        if (published(f) && f.isAnnotationPresent(Deprecated.class))
          deprecated.add("F " + c.getName() + "#" + f.getName());
    }
    for (Path root : List.of(MAIN, TESTING))
      try (Stream<Path> files = Files.walk(root)) {
        for (Path f : files.filter(p -> p.toString().endsWith(".java")).sorted().toList())
          if (Pattern.compile("@deprecated\\b|@Deprecated\\b").matcher(Files.readString(f)).find())
            deprecated.add("source " + root.relativize(f));
      }
    deprecated.removeAll(allowed);
    assertEquals(
        List.of(), deprecated, "deprecated: remove it, or record the decision and allow it");
  }

  /**
   * No published static method has the name and the return type of an instance method of its
   * class. Java lets a static method be called through an instance, and such a call ignores the
   * instance: {@code KeyQuery.ids(String...)}, once static, read as a filter ({@code
   * query.ids("a")}) but started a new query, silently dropping the filters of the one it was
   * called on, and with them a LocalKeys scope's boundary. ({@code Request.operation(Operation)}
   * returns a builder, and the getter {@code operation()} an {@code Operation}: a call through a
   * request does not type-check as the other.)
   */
  @Test
  void noStaticMethodPassesForAnInstanceMethod() throws Exception {
    List<String> shared = new ArrayList<>();
    for (Class<?> c : currentAndTesting()) {
      if (!visible(c)) continue;
      for (Method m : c.getMethods()) {
        if (!Modifier.isStatic(m.getModifiers())) continue;
        for (Method i : c.getMethods())
          if (!Modifier.isStatic(i.getModifiers())
              && i.getName().equals(m.getName())
              && (i.getReturnType().isAssignableFrom(m.getReturnType())
                  || m.getReturnType().isAssignableFrom(i.getReturnType()))) {
            shared.add(c.getName() + "#" + m.getName() + params(m.getParameterTypes()));
            break;
          }
      }
    }
    assertEquals(
        List.of(), shared, "rename the static method: a call through an instance ignores it");
  }

  /** No public or protected field can be assigned: only constants (static final). */
  @Test
  void noPublishedFieldIsMutable() throws Exception {
    List<String> mutable = new ArrayList<>();
    for (Class<?> c : currentAndTesting())
      if (visible(c))
        for (Field f : c.getDeclaredFields())
          if (published(f)
              && !(Modifier.isStatic(f.getModifiers()) && Modifier.isFinal(f.getModifiers())))
            mutable.add(c.getName() + "#" + f.getName());
    assertEquals(List.of(), mutable);
  }

  /**
   * The overloads a bare {@code null} makes ambiguous (same name and arity, differing in one
   * parameter whose two types are unrelated references) are the reviewed ones, where a null is
   * misuse anyway and the cast a caller adds names the kind of object. A new one fails here:
   * choose another name, or add it with its reason. The file passwords taken as a {@code char[]}
   * or a {@code Supplier<char[]>} follow {@code tls(SSLContext)} and {@code tls(Supplier)}: a value
   * or its source, and a null password is refused either way.
   */
  @Test
  void theNullAmbiguousOverloadsAreTheReviewedOnes() throws Exception {
    SortedSet<String> found = new TreeSet<>();
    for (Class<?> c : currentAndTesting()) {
      if (!visible(c)) continue;
      Method[] ms = c.getMethods();
      for (Method x : ms)
        for (Method y : ms) {
          if (x == y
              || !x.getName().equals(y.getName())
              || x.getParameterCount() != y.getParameterCount()) continue;
          if (x.getDeclaringClass().getName().startsWith("java.") || x.isBridge() || y.isBridge())
            continue;
          Class<?>[] p = x.getParameterTypes(), q = y.getParameterTypes();
          int differ = -1, count = 0;
          for (int k = 0; k < p.length; k++)
            if (p[k] != q[k]) {
              count++;
              differ = k;
            }
          if (count != 1 || p[differ].isPrimitive() || q[differ].isPrimitive()) continue;
          if (p[differ].isAssignableFrom(q[differ]) || q[differ].isAssignableFrom(p[differ]))
            continue;
          String a = p[differ].getSimpleName(), b = q[differ].getSimpleName();
          if (a.compareTo(b) > 0) continue;
          found.add(
              c.getName().substring("dev.keytend.kmip.".length())
                  + "."
                  + x.getName()
                  + "#"
                  + differ
                  + " "
                  + a
                  + "|"
                  + b);
        }
    }
    assertEquals(
        List.of(
            "client.RequestOptions$Builder.asynchronous#0 AsynchronousIndicator|Boolean",
            // KeyQuery.ids(String...) and ids(Collection): the same filter, from either.
            "kms.KeyQuery.ids#0 Collection|String[]",
            "kms.KmsConfig$Builder.clientIdentityKeyStore#1 Supplier|char[]",
            "kms.KmsConfig$Builder.clientIdentityPem#2 Supplier|char[]",
            "kms.KmsConfig$Builder.tls#0 SSLContext|Supplier",
            "kms.KmsConfig$Builder.trustStore#1 Supplier|char[]",
            "kms.KmsKeys.current#0 KeyHandle|String",
            "kms.KmsKeys.register#0 PrivateKey|PublicKey",
            "kms.KmsKeys.register#0 PrivateKey|SecretKey",
            "kms.KmsKeys.register#0 PrivateKey|X509Certificate",
            "kms.KmsKeys.register#0 PublicKey|SecretKey",
            "kms.KmsKeys.register#0 PublicKey|X509Certificate",
            "kms.KmsKeys.register#0 SecretKey|X509Certificate",
            "model.Credentials.usernamePassword#1 String|char[]",
            "model.Ttlv.structure#1 List|Ttlv[]",
            "model.UsageMask.of#0 Collection|CryptographicUsageMask[]",
            "testing.InMemoryKmipServer.failNext#1 Fault|ResultReason",
            "transport.TlsTransport.builder#2 SSLContext|Supplier"),
        List.copyOf(found));
  }
}
