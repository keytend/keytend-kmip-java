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

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;

/** The launcher's runtime check: a missing JAR is said before a command runs, a late one after. */
class MainTest {
  @Test
  void everyRuntimeLibraryIsOnTheTestClassPath() {
    assertNull(Main.missing(Main.RUNTIME));
  }

  @Test
  void eachLibraryOfTheManifestHasOneClassThatIsLookedForAtStart() throws IOException {
    // The runtime class path that lib/ and the manifest's Class-Path are made of (pom.xml writes
    // it): a runtime dependency added later fails here until Main.RUNTIME names one of its classes.
    String classPath =
        Files.readString(Path.of("target", "runtime-class-path.txt"), StandardCharsets.UTF_8)
            .strip();
    List<String> libraries = List.of(classPath.split(File.pathSeparator));
    for (String library : libraries) {
      List<String> found = new ArrayList<>();
      for (String c : Main.RUNTIME) if (provides(Path.of(library), c)) found.add(c);
      assertEquals(1, found.size(), library + " provides one class of Main.RUNTIME: " + found);
    }
    assertEquals(Main.RUNTIME.size(), libraries.size(), "one class per library: " + libraries);
  }

  /** Whether {@code library}, a JAR or a directory of classes, has the class {@code name}. */
  static boolean provides(Path library, String name) throws IOException {
    String entry = name.replace('.', '/') + ".class";
    if (Files.isDirectory(library)) return Files.exists(library.resolve(entry));
    try (JarFile jar = new JarFile(library.toFile())) {
      return jar.getEntry(entry) != null;
    }
  }

  @Test
  void aMissingRuntimeJarStopsBeforeTheCommandRuns() {
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    AtomicBoolean ran = new AtomicBoolean();
    List<String> runtime = new ArrayList<>(Main.RUNTIME);
    runtime.add(1, "tools.jackson.core.NoSuchClass");
    int code =
        Main.run(
            runtime,
            () -> {
              ran.set(true);
              return 0;
            },
            new PrintStream(err, true, StandardCharsets.UTF_8));
    assertEquals(2, code);
    assertFalse(ran.get(), "nothing was sent");
    String said = err.toString(StandardCharsets.UTF_8);
    assertTrue(said.contains("tools.jackson.core.NoSuchClass not found"), said);
    assertTrue(said.contains("Nothing was sent"), said);
  }

  @Test
  void aClassMissingPartWayIsAFailureThatMayHaveMadeItsChange() {
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    int code =
        Main.run(
            Main.RUNTIME,
            () -> {
              throw new NoClassDefFoundError("tools/jackson/core/ObjectWriteContext");
            },
            new PrintStream(err, true, StandardCharsets.UTF_8));
    assertEquals(1, code, "not 2: a change may have been made");
    String said = err.toString(StandardCharsets.UTF_8);
    assertTrue(said.contains("may have been made"), said);
  }
}
