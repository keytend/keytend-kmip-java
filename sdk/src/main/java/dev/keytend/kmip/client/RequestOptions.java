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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Optional request header fields. Each is a KMIP Request Header field of the same name, and null
 * leaves it out. Build one with {@link #builder()}.
 *
 * @param maximumResponseSize Maximum Response Size, in bytes; at least 1
 * @param authentication Authentication, holding one or more Credential structures
 * @param asynchronous the KMIP 1.x Asynchronous Indicator
 * @param batchOrder Batch Order Option
 * @param batchError Batch Error Continuation Option
 * @param timestamp Time Stamp, in whole seconds
 * @param attestationCapable Attestation Capable Indicator
 * @param attestationTypes Attestation Type values; empty for none
 * @param clientCorrelation Client Correlation Value
 * @param serverCorrelation Server Correlation Value
 * @param asynchronousMode the KMIP 2.x Asynchronous Indicator enumeration
 * @since 0.10.0
 */
public record RequestOptions(
    Integer maximumResponseSize,
    Ttlv authentication,
    Boolean asynchronous,
    Boolean batchOrder,
    Enums.BatchErrorContinuation batchError,
    Instant timestamp,
    Boolean attestationCapable,
    List<Ttlv> attestationTypes,
    String clientCorrelation,
    String serverCorrelation,
    Enums.AsynchronousIndicator asynchronousMode) {
  public static final RequestOptions DEFAULT =
      new RequestOptions(null, null, null, null, null, null, null, List.of(), null, null);

  public RequestOptions(
      Integer maximumResponseSize,
      Ttlv authentication,
      Boolean asynchronous,
      Boolean batchOrder,
      Enums.BatchErrorContinuation batchError,
      Instant timestamp,
      Boolean attestationCapable,
      List<Ttlv> attestationTypes,
      String clientCorrelation,
      String serverCorrelation) {
    this(
        maximumResponseSize,
        authentication,
        asynchronous,
        batchOrder,
        batchError,
        timestamp,
        attestationCapable,
        attestationTypes,
        clientCorrelation,
        serverCorrelation,
        null);
  }

  public RequestOptions {
    attestationTypes = List.copyOf(attestationTypes);
    if (maximumResponseSize != null && maximumResponseSize < 1)
      throw new IllegalArgumentException("Invalid maximum response size");
    if (authentication != null && authentication.tag() != AUTHENTICATION.code())
      throw new IllegalArgumentException("Expected Authentication");
    if (timestamp != null && !timestamp.truncatedTo(ChronoUnit.SECONDS).equals(timestamp))
      throw new IllegalArgumentException(
          "KMIP DateTime has second precision; truncate the timestamp to seconds");
  }

  /** A builder naming every header option; prefer it to the positional constructors. */
  public static Builder builder() {
    return new Builder(DEFAULT);
  }

  /** A builder starting from these options. */
  public Builder toBuilder() {
    return new Builder(this);
  }

  /** Named setters for every request header option. Null clears an option. */
  public static final class Builder {
    private Integer maximumResponseSize;
    private Ttlv authentication;
    private Boolean asynchronous, batchOrder, attestationCapable;
    private Enums.BatchErrorContinuation batchError;
    private Instant timestamp;
    private List<Ttlv> attestationTypes;
    private String clientCorrelation, serverCorrelation;
    private Enums.AsynchronousIndicator asynchronousMode;

    private Builder(RequestOptions o) {
      maximumResponseSize = o.maximumResponseSize;
      authentication = o.authentication;
      asynchronous = o.asynchronous;
      batchOrder = o.batchOrder;
      batchError = o.batchError;
      timestamp = o.timestamp;
      attestationCapable = o.attestationCapable;
      attestationTypes = o.attestationTypes;
      clientCorrelation = o.clientCorrelation;
      serverCorrelation = o.serverCorrelation;
      asynchronousMode = o.asynchronousMode;
    }

    public Builder maximumResponseSize(Integer bytes) {
      maximumResponseSize = bytes;
      return this;
    }

    /** An Authentication structure, or a single Credential to wrap in one. */
    public Builder authentication(Ttlv value) {
      authentication =
          value != null && value.tag() == CREDENTIAL.code()
              ? Credentials.authentication(value)
              : value;
      return this;
    }

    /** KMIP 1.x Asynchronous Indicator; 2.x maps true/false to Optional/Prohibited. */
    public Builder asynchronous(Boolean value) {
      asynchronous = value;
      asynchronousMode = null;
      return this;
    }

    /** KMIP 2.x Asynchronous Indicator enumeration. */
    public Builder asynchronous(Enums.AsynchronousIndicator mode) {
      asynchronousMode = mode;
      asynchronous = null;
      return this;
    }

    public Builder batchOrder(Boolean ordered) {
      batchOrder = ordered;
      return this;
    }

    public Builder batchErrorContinuation(Enums.BatchErrorContinuation option) {
      batchError = option;
      return this;
    }

    /** The request Time Stamp; must have whole seconds. */
    public Builder timestamp(Instant value) {
      if (value != null && !value.truncatedTo(ChronoUnit.SECONDS).equals(value))
        throw new IllegalArgumentException(
            "KMIP DateTime has second precision; truncate the timestamp to seconds");
      timestamp = value;
      return this;
    }

    public Builder attestationCapable(Boolean value) {
      attestationCapable = value;
      return this;
    }

    public Builder attestationTypes(List<Ttlv> types) {
      attestationTypes = List.copyOf(types);
      return this;
    }

    public Builder correlation(String client, String server) {
      clientCorrelation = client;
      serverCorrelation = server;
      return this;
    }

    public RequestOptions build() {
      return new RequestOptions(
          maximumResponseSize,
          authentication,
          asynchronous,
          batchOrder,
          batchError,
          timestamp,
          attestationCapable,
          attestationTypes,
          clientCorrelation,
          serverCorrelation,
          asynchronousMode);
    }
  }

  /**
   * An Authentication structure with one username/password Credential. KMIP sends the password as
   * a Text String, so it is held as a {@code String} inside the request; the caller can still
   * erase its own array.
   */
  public static Ttlv passwordAuthentication(String username, char[] password) {
    return Credentials.authentication(Credentials.usernamePassword(username, password));
  }

  /** Sets the Authentication header field; a bare Credential is wrapped in Authentication. */
  public RequestOptions authentication(Ttlv value) {
    if (value != null && value.tag() == CREDENTIAL.code())
      value = Credentials.authentication(value);
    return new RequestOptions(
        maximumResponseSize,
        value,
        asynchronous,
        batchOrder,
        batchError,
        timestamp,
        attestationCapable,
        attestationTypes,
        clientCorrelation,
        serverCorrelation,
        asynchronousMode);
  }

  public RequestOptions asynchronous(boolean value) {
    return new RequestOptions(
        maximumResponseSize,
        authentication,
        value,
        batchOrder,
        batchError,
        timestamp,
        attestationCapable,
        attestationTypes,
        clientCorrelation,
        serverCorrelation,
        null);
  }

  public RequestOptions asynchronous(Enums.AsynchronousIndicator mode) {
    return new RequestOptions(
        maximumResponseSize,
        authentication,
        null,
        batchOrder,
        batchError,
        timestamp,
        attestationCapable,
        attestationTypes,
        clientCorrelation,
        serverCorrelation,
        mode);
  }

  public RequestOptions batching(boolean ordered, Enums.BatchErrorContinuation continuation) {
    return new RequestOptions(
        maximumResponseSize,
        authentication,
        asynchronous,
        ordered,
        continuation,
        timestamp,
        attestationCapable,
        attestationTypes,
        clientCorrelation,
        serverCorrelation,
        asynchronousMode);
  }

  public RequestOptions correlation(String client, String server) {
    return new RequestOptions(
        maximumResponseSize,
        authentication,
        asynchronous,
        batchOrder,
        batchError,
        timestamp,
        attestationCapable,
        attestationTypes,
        client,
        server,
        asynchronousMode);
  }

  @Override
  public String toString() {
    return "RequestOptions[header options redacted]";
  }
}
