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

package dev.keytend.kmip.codec;

import dev.keytend.kmip.model.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.xml.stream.*;

/**
 * OASIS XML profile, including generic extension elements and symbolic attribute values. DTDs are
 * forbidden. Decoding is bounded by input bytes, nesting depth and element count (default {@link
 * TtlvCodec#DEFAULT_MAX_ELEMENTS}, as for TTLV).
 *
 * @since 0.10.0
 */
public final class XmlCodec {
  private final int maxBytes, maxDepth, maxElements;

  /** A codec with the default limits of {@link TtlvCodec}. */
  public XmlCodec() {
    this(TtlvCodec.DEFAULT_MAX_BYTES, TtlvCodec.DEFAULT_MAX_DEPTH);
  }

  /**
   * A codec with these limits and {@link TtlvCodec#DEFAULT_MAX_ELEMENTS}; see {@link #XmlCodec(int,
   * int, int)}.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   */
  public XmlCodec(int maxBytes, int maxDepth) {
    this(maxBytes, maxDepth, TtlvCodec.DEFAULT_MAX_ELEMENTS);
  }

  /**
   * A codec with these limits. Size and nesting apply when encoding and when decoding; the
   * element count applies when decoding.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   * @param maxElements the most values in one decoded message; at least 1
   * @throws IllegalArgumentException if a limit is below its minimum
   */
  public XmlCodec(int maxBytes, int maxDepth, int maxElements) {
    if (maxBytes < 8 || maxDepth < 1 || maxElements < 1)
      throw new IllegalArgumentException("Invalid limits");
    this.maxBytes = maxBytes;
    this.maxDepth = maxDepth;
    this.maxElements = maxElements;
  }

  /**
   * Encodes one TTLV value in the XML profile, as UTF-8.
   *
   * @param n the value
   * @return the encoded bytes
   * @throws IOException if {@code n} exceeds the size or nesting limit, or holds a value that XML
   *     1.0 cannot represent
   */
  public byte[] encode(Ttlv n) throws IOException {
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      XMLStreamWriter w = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(out, "UTF-8");
      write(w, n, 0);
      w.close();
      byte[] encoded =
          out.toString(StandardCharsets.UTF_8)
              .replace("\r", "&#13;")
              .replace("\n", "&#10;")
              .replace("\t", "&#9;")
              .getBytes(StandardCharsets.UTF_8);
      if (encoded.length > maxBytes) throw new IOException("XML message exceeds limit");
      return encoded;
    } catch (XMLStreamException e) {
      throw new IOException("XML encoding failed", e);
    }
  }

  private void write(XMLStreamWriter w, Ttlv n, int depth) throws XMLStreamException, IOException {
    if (depth >= maxDepth) throw new IOException("XML nesting limit");
    if (n.standardTag().isPresent()) w.writeStartElement(n.tagName());
    else {
      w.writeStartElement("TTLV");
      w.writeAttribute("tag", n.tagName());
    }
    if (n.type() == Ttlv.Type.STRUCTURE) {
      for (Ttlv c : n.children()) write(w, c, depth + 1);
    } else {
      w.writeAttribute("type", TextValues.typeName(n.type()));
      String value = TextValues.scalarText(n);
      for (int i = 0; i < value.length(); i++) {
        int cp = value.codePointAt(i);
        if (Character.isSupplementaryCodePoint(cp)) i++;
        if (cp != 9
            && cp != 10
            && cp != 13
            && (cp < 32 || cp == 0xfffe || cp == 0xffff || (cp >= 0xd800 && cp <= 0xdfff)))
          throw new IOException("Value cannot be represented in XML 1.0");
      }
      w.writeAttribute("value", value);
    }
    w.writeEndElement();
  }

  /**
   * Decodes exactly one TTLV value from XML; see {@link #decodeAll(byte[])}.
   *
   * @param bytes the XML document
   * @return the value
   * @throws DecodeException for malformed or oversized input, or not exactly one value
   */
  public Ttlv decode(byte[] bytes) throws IOException {
    List<Ttlv> nodes = decodeAll(bytes);
    if (nodes.size() != 1) throw new DecodeException("Expected exactly one XML TTLV value");
    return nodes.get(0);
  }

  /**
   * Reads either one TTLV or an OASIS test-case KMIP wrapper containing multiple messages.
   *
   * @param bytes the XML document
   * @return the values, in document order
   *
   * @throws DecodeException for malformed or oversized input; its message never contains input
   *     values
   */
  public List<Ttlv> decodeAll(byte[] bytes) throws IOException {
    if (bytes.length > maxBytes) throw new DecodeException("XML message exceeds limit");
    // The JDK's own StAX, whatever the system properties or the class path name: another
    // implementation would change what is accepted, the limits' behavior and the messages.
    XMLInputFactory f = XMLInputFactory.newDefaultFactory();
    f.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    f.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
    f.setXMLResolver(
        (publicId, systemId, baseURI, namespace) -> {
          throw new XMLStreamException("External entities forbidden");
        });
    try {
      XMLStreamReader r = f.createXMLStreamReader(new ByteArrayInputStream(bytes), "UTF-8");
      List<Ttlv> nodes = new ArrayList<>();
      int[] elements = {0};
      while (r.hasNext()) {
        int event = r.next();
        if (event == XMLStreamConstants.DTD) throw new TextValues.Malformed("DTDs forbidden");
        if (event == XMLStreamConstants.START_ELEMENT) {
          if (r.getLocalName().equals("KMIP")) continue;
          nodes.add(read(r, 0, null, elements));
        }
      }
      r.close();
      return List.copyOf(nodes);
    } catch (XMLStreamException e) {
      // Parser messages can quote the input; keep only the position.
      Location at = e.getLocation();
      throw new DecodeException(
          "Malformed KMIP XML"
              + (at == null
                  ? ""
                  : " at line " + at.getLineNumber() + ", column " + at.getColumnNumber()),
          e);
    } catch (RuntimeException e) {
      throw new DecodeException("Malformed KMIP XML" + TextValues.detail(e), e);
    }
  }

  private Ttlv read(XMLStreamReader r, int depth, String attributeName, int[] elements)
      throws XMLStreamException {
    if (depth >= maxDepth) throw new TextValues.Malformed("XML nesting limit");
    if (++elements[0] > maxElements) throw new TextValues.Malformed("XML element limit");
    String local = r.getLocalName();
    String tagName = local.equals("TTLV") ? r.getAttributeValue(null, "tag") : local;
    int tag = TextValues.tag(tagName);
    String typeName = r.getAttributeValue(null, "type");
    Ttlv.Type type = typeName == null ? Ttlv.Type.STRUCTURE : TextValues.type(typeName);
    String scalar = r.getAttributeValue(null, "value");
    List<Ttlv> children = new ArrayList<>();
    while (r.hasNext()) {
      int event = r.next();
      if (event == XMLStreamConstants.DTD || event == XMLStreamConstants.ENTITY_REFERENCE)
        throw new TextValues.Malformed("Entities forbidden");
      if (event == XMLStreamConstants.START_ELEMENT) {
        if (type != Ttlv.Type.STRUCTURE)
          throw new TextValues.Malformed("Scalar element has children");
        Ttlv child = read(r, depth + 1, attributeName, elements);
        children.add(child);
        if (child.tag() == Tag.ATTRIBUTE_NAME.code()) attributeName = child.textValue();
      } else if (event == XMLStreamConstants.END_ELEMENT) break;
      else if (event == XMLStreamConstants.CHARACTERS && !r.isWhiteSpace())
        throw new TextValues.Malformed("Unexpected XML text");
    }
    if (type == Ttlv.Type.STRUCTURE) {
      if (scalar != null) throw new TextValues.Malformed("Structure has scalar value");
      return Ttlv.structure(tag, children);
    }
    if (scalar == null) throw new TextValues.Malformed("Scalar missing value");
    return TextValues.scalar(tag, type, scalar, attributeName);
  }
}
