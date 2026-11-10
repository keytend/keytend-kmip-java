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

package dev.keytend.kmip.client;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * An operation and its lossless request payload; builder methods preserve field order.
 *
 * <p>Standard operations are named by {@link #operation()}. A vendor or future operation code
 * ({@link #operation(int)}) has no {@link Operation} constant: {@code operation()} is null,
 * {@link #operationCode()} holds the code, and the payload is sent exactly as built, without
 * version conversion. Two requests are equal when their operation, payload, batch ID,
 * extensions and ephemeral setting are equal.
 *
 * @since 0.10.0
 */
public final class Request {
  private final Operation operation;
  private final int operationCode;
  private final Ttlv payload;
  private final byte[] batchId;
  private final List<Ttlv> extensions;
  private final Ttlv ephemeral;

  public Request(
      Operation operation, Ttlv payload, byte[] batchId, List<Ttlv> extensions, Ttlv ephemeral) {
    this(
        Objects.requireNonNull(operation, "operation"),
        operation.code(),
        payload,
        batchId,
        extensions,
        ephemeral);
  }

  public Request(Operation operation, Ttlv payload, byte[] batchId, List<Ttlv> extensions) {
    this(operation, payload, batchId, extensions, null);
  }

  private Request(
      Operation operation,
      int operationCode,
      Ttlv payload,
      byte[] batchId,
      List<Ttlv> extensions,
      Ttlv ephemeral) {
    Objects.requireNonNull(payload, "payload");
    if (payload.tag() != REQUEST_PAYLOAD.code() || payload.type() != Ttlv.Type.STRUCTURE)
      throw new IllegalArgumentException("Expected RequestPayload structure");
    this.operation = operation;
    this.operationCode = operationCode;
    this.payload = payload;
    this.batchId = batchId == null ? null : batchId.clone();
    this.extensions = List.copyOf(Objects.requireNonNull(extensions, "extensions"));
    for (Ttlv e : this.extensions)
      if (e.tag() != MESSAGE_EXTENSION.code())
        throw new IllegalArgumentException("Expected MessageExtension");
    if (ephemeral != null && ephemeral.tag() != EPHEMERAL.code())
      throw new IllegalArgumentException("Expected Ephemeral");
    this.ephemeral = ephemeral;
  }

  /** The standard operation, or null for a vendor or unknown {@link #operationCode()}. */
  public Operation operation() {
    return operation;
  }

  /** The wire operation code. */
  public int operationCode() {
    return operationCode;
  }

  public Ttlv payload() {
    return payload;
  }

  /** The explicit Unique Batch Item ID, or null when the SDK assigns one. */
  public byte[] batchId() {
    return batchId == null ? null : batchId.clone();
  }

  public List<Ttlv> extensions() {
    return extensions;
  }

  /** The KMIP 3.0 Ephemeral field, or null. */
  public Ttlv ephemeral() {
    return ephemeral;
  }

  public static Builder operation(Operation op) {
    return new Builder(Objects.requireNonNull(op, "operation"), op.code());
  }

  /**
   * A request for a raw operation code, for vendor extensions ({@code 0x8XXXXXXX}) or operations
   * newer than this SDK. A code with a standard {@link Operation} constant builds that operation.
   */
  public static Builder operation(int code) {
    for (Operation op : Operation.values()) if (op.code() == code) return operation(op);
    return new Builder(null, code);
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof Request r
        && r.operationCode == operationCode
        && r.payload.equals(payload)
        && Arrays.equals(r.batchId, batchId)
        && r.extensions.equals(extensions)
        && Objects.equals(r.ephemeral, ephemeral);
  }

  @Override
  public int hashCode() {
    return Objects.hash(operationCode, payload, Arrays.hashCode(batchId), extensions, ephemeral);
  }

  /** Names the operation and batch ID; payload values are not shown. */
  @Override
  public String toString() {
    return "Request[operation="
        + (operation == null ? String.format("0x%08X", operationCode) : operation.wireName())
        + (batchId == null ? "" : ", batchId=" + HexFormat.of().formatHex(batchId))
        + ", payload="
        + payload
        + "]";
  }

  public static final class Builder {
    private final Operation operation;
    private final int operationCode;
    private final List<Ttlv> fields = new ArrayList<>(), extensions = new ArrayList<>();
    private byte[] batchId;
    private Ttlv ephemeral;

    private Builder(Operation op, int code) {
      operation = op;
      operationCode = code;
    }

    public Builder add(Ttlv... nodes) {
      fields.addAll(List.of(nodes));
      return this;
    }

    public Builder uniqueIdentifier(String id) {
      return add(text(UNIQUE_IDENTIFIER, id));
    }

    public Builder attributes(Ttlv... values) {
      return add(ModernAttributes.of(values));
    }

    public Builder attributeReference(Tag tag) {
      return add(ModernAttributes.reference(tag));
    }

    public Builder currentAttribute(Ttlv value) {
      return add(ModernAttributes.currentAttribute(value));
    }

    public Builder newAttribute(Ttlv value) {
      return add(ModernAttributes.newAttribute(value));
    }

    public Builder attribute(Ttlv attribute) {
      if (attribute.tag() != ATTRIBUTE.code())
        throw new IllegalArgumentException("Expected Attribute");
      return add(attribute);
    }

    public Builder template(Ttlv... attributes) {
      return add(Attributes.template(attributes));
    }

    public Builder data(byte[] data) {
      return add(bytes(DATA, data));
    }

    public Builder cryptographicParameters(Ttlv... fields) {
      return add(Structures.structure(CRYPTOGRAPHIC_PARAMETERS, fields));
    }

    public Builder ephemeral(Enums.Ephemeral value) {
      ephemeral = enumeration(EPHEMERAL, value);
      return this;
    }

    public Builder batchId(byte[] id) {
      batchId = id.clone();
      return this;
    }

    public Builder extension(Ttlv extension) {
      extensions.add(extension);
      return this;
    }

    public Request build() {
      Ttlv payload =
          operation == null
              ? structure(REQUEST_PAYLOAD, fields)
              : Structures.requestPayload(operation, fields);
      return new Request(operation, operationCode, payload, batchId, extensions, ephemeral);
    }
  }
}
