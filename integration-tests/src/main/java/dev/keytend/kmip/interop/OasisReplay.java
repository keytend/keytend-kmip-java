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

package dev.keytend.kmip.interop;

import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.codec.XmlCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.regex.*;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.*;

/**
 * Replays complete original OASIS scenarios, binding server-generated identifiers and binary
 * results. Expected fields must match except explicitly permitted profile variations; additional
 * response fields are permitted. Audit mismatches are reported, never turned into successful
 * checks. Use a dedicated test server: fixtures change and destroy objects.
 */
public final class OasisReplay {
  private final KmipTransport transport;
  private final ProtocolVersion version;
  private final XmlCodec xml = new XmlCodec();
  private final boolean literal = Boolean.getBoolean("kmip.oasis.literal");

  public OasisReplay(KmipTransport transport, ProtocolVersion version) {
    this.transport = transport;
    this.version = version;
  }

  public List<InteropSuite.Check> runAll(Path fixtures) throws Exception {
    List<InteropSuite.Check> results = new ArrayList<>();
    List<Path> files;
    try (var walk = Files.walk(fixtures)) {
      files = walk.filter(p -> p.toString().endsWith(".xml")).sorted().toList();
    }
    for (Path file : files) {
      String name = fixtures.relativize(file).toString();
      try {
        int calls = run(file);
        results.add(
            new InteropSuite.Check(name, calls == 0 ? "VERSION" : "PASS", calls + " exchanges"));
      } catch (Unsupported e) {
        results.add(new InteropSuite.Check(name, "UNSUPPORTED", e.getMessage()));
      } catch (Exception | AssertionError e) {
        results.add(
            new InteropSuite.Check(
                name,
                "FAIL",
                e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
      }
    }
    return List.copyOf(results);
  }

  private int run(Path path) throws Exception {
    String text = Files.readString(path).replace("</KMIP>\n\n</KMIP>", "</KMIP>");
    Document document = parse(text.getBytes(StandardCharsets.UTF_8));
    List<Element> messages = elements(document.getDocumentElement());
    Map<String, String> variables = new HashMap<>();
    Set<String> generated = new HashSet<>();
    int exchanges = 0;
    for (int i = 0; i < messages.size(); i += 2) {
      if (i + 1 >= messages.size()) throw new IOException("Unpaired OASIS request");
      Element request = messages.get(i), expected = messages.get(i + 1);
      expandRequest(request, variables);
      Ttlv raw = xml.decode(serialize(request));
      if (Messages.version(raw.require(REQUEST_HEADER)) != version) return 0;
      Ttlv actual = transport.exchange(raw);
      exchanges++;
      // Inspect unsupported responses before binding variables from a success payload
      // that the peer did not return.
      List<Element> expectedBatches =
          elements(expected).stream().filter(e -> e.getTagName().equals("BatchItem")).toList();
      List<Ttlv> actualBatches = actual.children(BATCH_ITEM);
      for (int n = 0; n < Math.min(expectedBatches.size(), actualBatches.size()); n++) {
        String status =
            elements(expectedBatches.get(n)).stream()
                .filter(e -> e.getTagName().equals("ResultStatus"))
                .map(e -> e.getAttribute("value"))
                .findFirst()
                .orElse("");
        Ttlv batch = actualBatches.get(n);
        int reason = batch.child(RESULT_REASON).map(Ttlv::intValue).orElse(-1);
        if ((status.equals("Success") || status.equals("0x00000000") || status.equals("0"))
            && batch.require(RESULT_STATUS).intValue() == 1
            && (reason == 5 || reason == 8))
          throw new Unsupported("Required operation/feature rejected, reason=" + reason);
      }
      List<Ttlv> requests = raw.children(BATCH_ITEM);
      for (int n = 0; n < Math.min(requests.size(), actualBatches.size()); n++) {
        int operation = requests.get(n).require(OPERATION).intValue();
        if (Set.of(1, 2, 4, 5, 6, 7, 29, 40, 41).contains(operation)
            && actualBatches.get(n).require(RESULT_STATUS).intValue() == 0) {
          var payload = actualBatches.get(n).child(RESPONSE_PAYLOAD);
          if (payload.isPresent())
            for (Tag tag :
                List.of(
                    UNIQUE_IDENTIFIER, PRIVATE_KEY_UNIQUE_IDENTIFIER, PUBLIC_KEY_UNIQUE_IDENTIFIER))
              for (Ttlv uid : payload.get().children(tag)) generated.add(uid.textValue());
        }
      }
      Element actualXml = parse(xml.encode(actual)).getDocumentElement();
      bindExpected(expected, actualXml, variables, generated, null);
      Ttlv expectedValue = xml.decode(serialize(expected));
      List<Ttlv> wanted = expectedValue.children(BATCH_ITEM),
          received = actual.children(BATCH_ITEM);
      for (int n = 0; n < Math.min(wanted.size(), received.size()); n++) {
        if (wanted.get(n).require(RESULT_STATUS).intValue() == 0
            && received.get(n).require(RESULT_STATUS).intValue() == 1) {
          int reason = received.get(n).child(RESULT_REASON).map(Ttlv::intValue).orElse(-1);
          if (reason == 5 || reason == 8)
            throw new Unsupported("Required operation/feature rejected, reason=" + reason);
        }
      }
      compare(expectedValue, actual);
    }
    return exchanges;
  }

  private static void expandRequest(Element element, Map<String, String> variables)
      throws IOException {
    if (element.hasAttribute("value")) {
      String value = element.getAttribute("value");
      String serverCorrelation = variables.get("server-correlation:" + value);
      element.setAttribute(
          "value",
          element.getTagName().equals("ServerCorrelationValue") && serverCorrelation != null
              ? serverCorrelation
              : resolve(value, variables));
    }
    for (Element child : elements(element)) expandRequest(child, variables);
  }

  private static String resolve(String value, Map<String, String> variables) throws IOException {
    if (value.startsWith("$NOW")) {
      String suffix = value.substring(4);
      return Instant.now()
          .plusSeconds(suffix.isEmpty() ? 0 : Long.parseLong(suffix))
          .truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
          .toString();
    }
    if (value.startsWith("$")) {
      String replacement = variables.get(value);
      if (replacement == null) throw new IOException("Unbound OASIS variable " + value);
      return replacement;
    }
    return value;
  }

  private void bindExpected(
      Element expected,
      Element actual,
      Map<String, String> variables,
      Set<String> generated,
      String object)
      throws Exception {
    if (actual.getTagName().equals("ResponsePayload")) {
      object =
          elements(actual).stream()
              .filter(e -> e.getTagName().equals("UniqueIdentifier"))
              .map(e -> e.getAttribute("value"))
              .findFirst()
              .orElse(null);
    }
    String value = expected.getAttribute("value");
    // OASIS Profiles 2.1 §4.1: free-form messages and digests of generated objects vary.
    // Known registered material remains exact, and a generated object's digest is bound
    // consistently for later responses rather than ignored.
    if (!literal && expected.getTagName().equals("ResultMessage"))
      expected.setAttribute("value", actual.getAttribute("value"));
    else if (!literal
        && expected.getTagName().equals("DigestValue")
        && generated.contains(object)) {
      Element digest = (Element) actual.getParentNode();
      if (xml.decode(serialize(digest)).require(HASHING_ALGORITHM).intValue()
              == Enums.HashingAlgorithm.SHA_256.code()
          && xml.decode(serialize(actual)).bytesValue().length != 32)
        throw new AssertionError("Invalid SHA-256 generated digest length");
      String format =
          elements(digest).stream()
              .filter(
                  e ->
                      e.getTagName().equals("KeyFormatType")
                          || e.getTagName().equals("HashingAlgorithm"))
              .map(e -> e.getTagName() + "=" + e.getAttribute("value"))
              .sorted()
              .reduce("", (a, b) -> a + ";" + b);
      String key = "generated-digest:" + object + format;
      String bound = variables.computeIfAbsent(key, ignored -> actual.getAttribute("value"));
      expected.setAttribute("value", bound);
    } else if (expected.getTagName().equals("ServerCorrelationValue")) {
      // Published example correlation strings are opaque server-generated values,
      // not fixed protocol constants. Bind them if a later request echoes one.
      variables.put("server-correlation:" + value, actual.getAttribute("value"));
      expected.setAttribute("value", actual.getAttribute("value"));
    } else if (value.startsWith("$NOW"))
      expected.setAttribute("value", actual.getAttribute("value"));
    else if (value.startsWith("$")) {
      String bound = variables.computeIfAbsent(value, ignored -> actual.getAttribute("value"));
      expected.setAttribute("value", bound);
    }
    Map<String, Integer> used = new HashMap<>();
    List<Element> actualChildren = elements(actual);
    for (Element child : elements(expected)) {
      String tag = child.getTagName();
      int ordinal = used.merge(tag, 1, Integer::sum) - 1;
      List<Element> candidates =
          actualChildren.stream().filter(c -> c.getTagName().equals(tag)).toList();
      if (ordinal >= candidates.size()) {
        if (!literal && tag.equals("ResultMessage")) {
          expected.removeChild(child);
          continue;
        }
        throw new AssertionError("Missing response field " + tag);
      }
      bindExpected(child, candidates.get(ordinal), variables, generated, object);
    }
  }

  private static void compare(Ttlv expected, Ttlv actual) {
    if (expected.tag() != actual.tag() || expected.type() != actual.type())
      throw new AssertionError("Type/tag mismatch for " + expected.tagName());
    if (expected.type() != Ttlv.Type.STRUCTURE) {
      if (!expected.equals(actual))
        throw new AssertionError("Value mismatch for " + expected.tagName());
      return;
    }
    List<Ttlv> remaining = new ArrayList<>(actual.children());
    for (Ttlv wanted : expected.children()) {
      // Attribute/operation lists may be returned in any order. Prefer a complete equal value.
      int at = remaining.indexOf(wanted);
      if (at >= 0) {
        remaining.remove(at);
        continue;
      }
      int candidate = -1;
      for (int i = 0; i < remaining.size(); i++)
        if (remaining.get(i).tag() == wanted.tag()) {
          candidate = i;
          break;
        }
      if (candidate < 0) throw new AssertionError("Missing response field " + wanted.tagName());
      compare(wanted, remaining.remove(candidate));
    }
  }

  private static List<Element> elements(Element element) {
    List<Element> out = new ArrayList<>();
    for (Node n = element.getFirstChild(); n != null; n = n.getNextSibling())
      if (n instanceof Element e) out.add(e);
    return out;
  }

  private static Document parse(byte[] xml) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    f.setFeature("http://xml.org/sax/features/external-general-entities", false);
    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    f.setXIncludeAware(false);
    f.setExpandEntityReferences(false);
    return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
  }

  private static byte[] serialize(Element element) throws Exception {
    TransformerFactory factory = TransformerFactory.newInstance();
    factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    var transformer = factory.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    transformer.transform(new DOMSource(element), new StreamResult(out));
    return out.toByteArray();
  }

  private static final class Unsupported extends Exception {
    Unsupported(String message) {
      super(message);
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 6)
      throw new IllegalArgumentException(
          "Usage: OasisReplay <server> <host> <port> <cert-dir> <fixture-dir> <version>"
              + " [report-dir]");
    Path certs = Path.of(args[3]);
    String[] parts = args[5].split("\\.");
    ProtocolVersion version =
        ProtocolVersion.of(Integer.parseInt(parts[0]), Integer.parseInt(parts[1]));
    try (var transport =
        new TlsTransport(
            args[1],
            Integer.parseInt(args[2]),
            Tls.context(
                certs.resolve("client.p12"), "changeit".toCharArray(), certs.resolve("ca.pem")))) {
      var checks = new OasisReplay(transport, version).runAll(Path.of(args[4]));
      for (var c : checks) System.out.println(c.outcome() + " " + c.name() + " " + c.detail());
      InteropSuite.writeReport(
          Path.of(args.length > 6 ? args[6] : "integration/reports")
              .resolve(
                  args[0] + "-oasis-" + version + "-jdk" + Runtime.version().feature() + ".json"),
          args[0],
          version,
          checks);
      long fail = checks.stream().filter(c -> c.outcome().equals("FAIL")).count();
      System.out.println("Audit: " + checks.size() + " scenarios, " + fail + " mismatches");
      if (Boolean.getBoolean("kmip.oasis.strict") && fail > 0)
        throw new AssertionError(fail + " OASIS replay mismatches");
    }
  }
}
