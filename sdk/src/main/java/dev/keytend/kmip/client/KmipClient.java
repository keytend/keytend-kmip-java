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

import dev.keytend.kmip.codec.DecodeException;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.*;
import java.net.SocketException;
import java.util.*;

/**
 * The KMIP protocol client. It sends requests at one protocol version over a {@link
 * KmipTransport} and returns the server's results. It speaks KMIP 1.1 to 1.4, 2.0, 2.1 and 3.0
 * CSD02. For ordinary key management, use {@link dev.keytend.kmip.kms.Kms} instead.
 *
 * <p>Get a client that owns its transport with {@link #negotiated(KmipTransport, VersionPolicy)}:
 *
 * <pre>{@code
 * try (KmipClient client = KmipClient.negotiated(
 *     new TlsTransport("kms.example.com", 5696, ssl),
 *     VersionPolicy.atLeast(ProtocolVersion.V1_4))) {
 *   String id = client.createSymmetricKey(Enums.CryptographicAlgorithm.AES, 256,
 *       Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT);
 *   client.activate(id);
 * }
 * }</pre>
 *
 * <p>{@code ssl} is an {@code SSLContext}, for example from {@link
 * dev.keytend.kmip.transport.Tls#context(java.nio.file.Path, char[], java.nio.file.Path)}. To run
 * one operation that {@code Kms} does not cover on an existing {@code Kms}, use the non-owning
 * client from {@link dev.keytend.kmip.kms.Kms#protocol()}.
 *
 * <p><b>Failures.</b>
 *
 * <ul>
 *   <li>{@link #call(Request)} and the convenience methods throw the unchecked {@link
 *       KmipException} when the server answers Failed, Pending or Undone. {@link
 *       #execute(Request)} returns such a result instead.
 *   <li>Transport and protocol problems are checked {@link IOException}s. A {@link
 *       ProtocolException} means a response arrived but was rejected.
 *   <li>After an {@code IOException}, the outcome of a mutation is unknown, unless it is a {@link
 *       dev.keytend.kmip.transport.RequestNotSentException}. Check the server before you repeat
 *       the mutation. Reads can be repeated.
 *   <li>The client never retries a request.
 *   <li>A request that the client's version cannot express fails with {@link
 *       IllegalArgumentException} before anything is sent.
 * </ul>
 *
 * <p>Thread safety follows the transport: a client over a {@link
 * dev.keytend.kmip.transport.TlsTransport} can be shared between threads. Guide: <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/protocol-layer.md">Protocol layer</a>.
 *
 * @since 0.10.0
 */
public final class KmipClient implements AutoCloseable {
  private final KmipTransport transport;
  private final ProtocolVersion version;
  private final RequestOptions options;
  private final Set<String> knownExtensions;
  private final int maximumBatchItems;
  private final boolean owner;

  /**
   * A client at a fixed version, without negotiation, with no request options. It owns {@code
   * transport}: {@link #close()} closes it.
   *
   * @param transport the transport to send over
   * @param version the protocol version of every request
   * @see #KmipClient(KmipTransport, ProtocolVersion, RequestOptions, Set, int)
   */
  public KmipClient(KmipTransport transport, ProtocolVersion version) {
    this(transport, version, RequestOptions.DEFAULT);
  }

  /**
   * A client at a fixed version with request options; see {@link #KmipClient(KmipTransport,
   * ProtocolVersion, RequestOptions, Set, int)}.
   *
   * @param transport the transport to send over; the client owns it
   * @param version the protocol version of every request
   * @param options the request header fields of every message
   */
  public KmipClient(KmipTransport transport, ProtocolVersion version, RequestOptions options) {
    this(transport, version, options, Set.of());
  }

  /**
   * A client at a fixed version that accepts the named critical message extensions; see {@link
   * #KmipClient(KmipTransport, ProtocolVersion, RequestOptions, Set, int)}.
   *
   * @param transport the transport to send over; the client owns it
   * @param version the protocol version of every request
   * @param options the request header fields of every message
   * @param knownExtensions the Vendor Identifications of critical message extensions to accept
   */
  public KmipClient(
      KmipTransport transport,
      ProtocolVersion version,
      RequestOptions options,
      Set<String> knownExtensions) {
    this(transport, version, options, knownExtensions, Messages.MAX_BATCH_ITEMS);
  }

  /**
   * A client at a fixed version, without negotiation. Use it when the version is already known;
   * otherwise prefer {@link #negotiated(KmipTransport, VersionPolicy, RequestOptions, Set, int)}.
   * The client owns {@code transport}: {@link #close()} closes it.
   *
   * @param transport the transport to send over
   * @param version the protocol version of every request
   * @param options the request header fields of every message sent without its own options
   *     ({@link RequestOptions#DEFAULT} sets none)
   * @param knownExtensions the Vendor Identifications of critical message extensions to accept. A
   *     response with any other critical extension fails with {@link ProtocolException}.
   * @param maximumBatchItems the most items in one request or response (the other constructors
   *     use 128). A larger request fails with {@link IllegalArgumentException}, a larger response
   *     with {@link ProtocolException}.
   * @throws IllegalArgumentException if {@code maximumBatchItems} is less than 1
   */
  public KmipClient(
      KmipTransport transport,
      ProtocolVersion version,
      RequestOptions options,
      Set<String> knownExtensions,
      int maximumBatchItems) {
    this(transport, version, options, knownExtensions, maximumBatchItems, true);
  }

  private KmipClient(
      KmipTransport transport,
      ProtocolVersion version,
      RequestOptions options,
      Set<String> knownExtensions,
      int maximumBatchItems,
      boolean owner) {
    if (maximumBatchItems < 1) throw new IllegalArgumentException("Invalid batch item limit");
    this.maximumBatchItems = maximumBatchItems;
    this.knownExtensions = Set.copyOf(knownExtensions);
    this.transport = Objects.requireNonNull(transport, "transport");
    this.version = Objects.requireNonNull(version, "version");
    this.options = Objects.requireNonNull(options, "options");
    this.owner = owner;
  }

  /**
   * Negotiates a version with Discover Versions and returns a client that owns {@code transport}.
   * It chooses the highest version the server offers that {@code policy} accepts.
   *
   * <p>The first request uses the policy's highest version. Some servers cannot answer a header of
   * another major version: they reply with an error, or close the connection. Discover Versions is
   * then sent again at a lower version: a lower version named in the error response's header,
   * else the highest accepted version of a lower major, else 1.4 to learn what the server offers.
   * At most three requests are sent. A closed connection leads to a retry only on the first.
   *
   * <p>If negotiation fails, the transport is closed and no other request has been sent.
   *
   * @param transport the transport; the returned client owns it
   * @param policy the versions to accept
   * @param options the request header fields of every message; see {@link
   *     #KmipClient(KmipTransport, ProtocolVersion, RequestOptions, Set, int)}
   * @param knownExtensions the Vendor Identifications of critical message extensions to accept
   * @param maximumBatchItems the most items in one request or response
   * @return the owning client at the chosen version
   * @throws VersionNegotiationException if the server offers no version the policy accepts
   * @throws KmipException if the server refuses Discover Versions for a reason other than the
   *     version, such as Permission Denied
   * @throws IOException if the transport fails or the responses are invalid
   */
  public static KmipClient negotiated(
      KmipTransport transport,
      VersionPolicy policy,
      RequestOptions options,
      Set<String> knownExtensions,
      int maximumBatchItems)
      throws IOException {
    return negotiated(
        transport, policy, options, knownExtensions, maximumBatchItems, CallContext.NONE);
  }

  /**
   * {@link #negotiated(KmipTransport, VersionPolicy, RequestOptions, Set, int)} within one
   * deadline: {@code context} bounds every Discover Versions request it sends (up to three), and
   * its cancellation stops the negotiation.
   *
   * @param transport the transport; the returned client owns it
   * @param policy the versions to accept
   * @param options the request header fields of every message
   * @param knownExtensions the Vendor Identifications of critical message extensions to accept
   * @param maximumBatchItems the most items in one request or response
   * @param context the deadline and cancellation for the whole negotiation
   * @return the owning client at the chosen version
   * @throws IOException as for the overload without {@code context}
   */
  public static KmipClient negotiated(
      KmipTransport transport,
      VersionPolicy policy,
      RequestOptions options,
      Set<String> knownExtensions,
      int maximumBatchItems,
      CallContext context)
      throws IOException {
    Objects.requireNonNull(context, "context");
    try {
      ProtocolVersion chosen =
          choose(transport, policy, options, knownExtensions, maximumBatchItems, context);
      return new KmipClient(transport, chosen, options, knownExtensions, maximumBatchItems, true);
    } catch (IOException | RuntimeException e) {
      try {
        transport.close();
      } catch (IOException suppressed) {
        e.addSuppressed(suppressed);
      }
      throw e;
    }
  }

  /**
   * {@link #negotiated(KmipTransport, VersionPolicy, RequestOptions, Set, int)} with no request
   * options, no known extensions and at most 128 batch items.
   *
   * @param transport the transport; the returned client owns it
   * @param policy the versions to accept
   * @return the owning client at the chosen version
   * @throws IOException as for the full overload, which also lists the other failures
   */
  public static KmipClient negotiated(KmipTransport transport, VersionPolicy policy)
      throws IOException {
    return negotiated(
        transport, policy, RequestOptions.DEFAULT, Set.of(), Messages.MAX_BATCH_ITEMS);
  }

  private static ProtocolVersion choose(
      KmipTransport transport,
      VersionPolicy policy,
      RequestOptions options,
      Set<String> knownExtensions,
      int maximumBatchItems,
      CallContext context)
      throws IOException {
    ProtocolVersion first = policy.highest();
    // If the server cannot answer a header, the next header is the version it stamped on its
    // error response (when that is a supported, lower version), else the highest version of a
    // lower major that the policy accepts, else 1.4 just to learn what the server offers. At most
    // three Discover Versions requests are sent.
    Deque<ProtocolVersion> headers = new ArrayDeque<>(List.of(first));
    Set<ProtocolVersion> tried = new HashSet<>();
    IOException failure = null;
    while (!headers.isEmpty() && tried.size() < 3) {
      ProtocolVersion header = headers.poll();
      if (!tried.add(header)) continue;
      List<ProtocolVersion> offered;
      try {
        offered =
            new KmipClient(transport, header, options, knownExtensions, maximumBatchItems, false)
                .discoverVersions(context);
      } catch (IllegalArgumentException refused) {
        // A transport that cannot send this header (hashed passwords need 2.0) keeps the first
        // failure.
        if (failure == null) throw refused;
        continue;
      } catch (KmipException e) {
        // Only an answer about the header is worth retrying with another version; anything else
        // (Authentication Not Successful, Permission Denied, ...) would just repeat, so report it.
        Integer reason = e.result().reason();
        boolean versionProblem =
            reason == null
                || reason == Enums.ResultReason.INVALID_MESSAGE.code()
                || reason == Enums.ResultReason.UNSUPPORTED_PROTOCOL_VERSION.code()
                || reason == Enums.ResultReason.OPERATION_NOT_SUPPORTED.code()
                || reason == Enums.ResultReason.FEATURE_NOT_SUPPORTED.code();
        if (!versionProblem) throw e;
        failure = retryWithStamp(e, header, failure, e.result().batchItem(), headers, policy);
        continue;
      } catch (ProtocolException e) {
        failure = retryWithStamp(e, header, failure, e.response(), headers, policy);
        continue;
      } catch (EOFException | SocketException dropped) {
        // Some servers close the connection on a header they cannot parse instead of answering.
        // Only the first request steps down for this, once: a connection that drops again is a
        // transport problem, not a version problem.
        if (tried.size() > 1) throw dropped;
        failure = retryWithStamp(dropped, header, failure, null, headers, policy);
        continue;
      }
      Optional<ProtocolVersion> chosen = policy.choose(offered);
      if (chosen.isEmpty()) throw new VersionNegotiationException(offered, policy);
      return chosen.get();
    }
    throw failure;
  }

  private static IOException retryWithStamp(
      Exception e,
      ProtocolVersion header,
      IOException previous,
      Ttlv raw,
      Deque<ProtocolVersion> headers,
      VersionPolicy policy) {
    IOException wrapped =
        e instanceof IOException io
            ? io
            : new IOException("Discover Versions failed with a " + header + " header", e);
    if (previous != null) wrapped.addSuppressed(previous);
    stamped(raw).filter(v -> v.code() < header.code()).ifPresent(headers::addFirst);
    if (headers.isEmpty()) {
      ProtocolVersion fallback = null;
      for (ProtocolVersion v : ProtocolVersion.values())
        if (v.major() < header.major() && policy.accepts(v)) fallback = v;
      if (fallback == null && !header.legacyAttributes()) fallback = ProtocolVersion.V1_4;
      if (fallback != null) headers.add(fallback);
    }
    return wrapped;
  }

  /** The protocol version in a rejected response's header, when it is one this SDK supports. */
  private static Optional<ProtocolVersion> stamped(Ttlv response) {
    try {
      if (response == null || response.tag() != RESPONSE_MESSAGE.code()) return Optional.empty();
      return Optional.of(Messages.version(response.require(RESPONSE_HEADER)));
    } catch (RuntimeException unsupported) {
      return Optional.empty();
    }
  }

  /**
   * The protocol version of every request this client sends.
   *
   * @return the version
   */
  public ProtocolVersion version() {
    return version;
  }

  /**
   * Sends one request and returns its result, whatever its status. Use it where Failed or Pending
   * is an answer to inspect: asynchronous operations and capability probes.
   *
   * @param request the request
   * @return the result; a failure is returned, not thrown
   * @throws IOException for a transport or protocol problem; then a mutation's outcome is unknown
   */
  public Result execute(Request request) throws IOException {
    return execute(request, CallContext.NONE);
  }

  /**
   * {@link #execute(Request)} bounded by a per-call deadline and cancellation.
   *
   * @param request the request
   * @param context the deadline and cancellation of this call
   * @return the result; a failure is returned, not thrown
   * @throws IOException for a transport or protocol problem; see {@link
   *     dev.keytend.kmip.transport.CallContext} for deadlines
   */
  public Result execute(Request request, CallContext context) throws IOException {
    return batch(List.of(request), options, context).results().get(0);
  }

  /**
   * Sends one request and requires Success.
   *
   * @param request the request
   * @return the successful result
   * @throws KmipException (unchecked) when the result is Failed, Pending or Undone; {@link
   *     KmipException#result()} holds it
   * @throws IOException for a transport or protocol problem; then a mutation's outcome is unknown
   */
  public Result call(Request request) throws IOException {
    return execute(request).requireSuccess();
  }

  /**
   * {@link #call(Request)} bounded by a per-call deadline and cancellation.
   *
   * @param request the request
   * @param context the deadline and cancellation of this call
   * @return the successful result
   * @throws IOException for a transport or protocol problem; see {@link
   *     dev.keytend.kmip.transport.CallContext} for deadlines
   */
  public Result call(Request request, CallContext context) throws IOException {
    return execute(request, context).requireSuccess();
  }

  /**
   * Sends {@code requests} as one message with this client's request options; see {@link
   * #batch(List, RequestOptions, CallContext)}.
   *
   * @param requests the batch items, in order
   * @return the response
   * @throws IOException for a transport or protocol problem
   */
  public Response batch(List<Request> requests) throws IOException {
    return batch(requests, options);
  }

  /**
   * Sends {@code requests} as one message with {@code options} instead of this client's; see
   * {@link #batch(List, RequestOptions, CallContext)}.
   *
   * @param requests the batch items, in order
   * @param options the request header fields of this message
   * @return the response
   * @throws IOException for a transport or protocol problem
   */
  public Response batch(List<Request> requests, RequestOptions options) throws IOException {
    return batch(requests, options, CallContext.NONE);
  }

  /**
   * Sends one batch. The response's results are not checked for success: a failed item is a
   * {@link Result} like any other. {@code context} bounds this call alone. A deadline or
   * cancellation after the request was written leaves a mutation's outcome unknown. Nothing is
   * retried.
   *
   * @param requests the batch items, in order: 1 to the client's maximum batch items
   * @param options the request header fields of this message
   * @param context the deadline and cancellation of this call
   * @return the response; see {@link Response} for how its results match the requests
   * @throws IllegalArgumentException before sending, for an empty or too large batch, or a request
   *     the client's version cannot express
   * @throws ProtocolException for a response that cannot be decoded (then without a response:
   *     {@link ProtocolException#response()} is null) or that violates the protocol; its message
   *     and cause chain carry no response values
   * @throws IOException for a transport failure
   */
  public Response batch(List<Request> requests, RequestOptions options, CallContext context)
      throws IOException {
    Ttlv message = Messages.request(version, List.copyOf(requests), options, maximumBatchItems);
    Ttlv response;
    try {
      response = transport.exchange(message, context);
    } catch (DecodeException malformed) {
      // The server answered with bytes that are not KMIP: a protocol violation, not an I/O
      // failure worth repeating. The message is fixed text and the cause is redacted.
      throw new ProtocolException(
          "Malformed KMIP response: " + malformed.getMessage(), null, malformed);
    }
    try {
      for (Ttlv batch : response.children(BATCH_ITEM))
        for (Ttlv extension : batch.children(MESSAGE_EXTENSION))
          if (extension.require(CRITICALITY_INDICATOR).booleanValue()
              && !knownExtensions.contains(extension.require(VENDOR_IDENTIFICATION).textValue()))
            throw new IOException("Unknown critical message extension");
      return Messages.correlate(message, Messages.response(response, maximumBatchItems));
    } catch (IOException e) {
      // Response checks report fixed text. A check that wraps another exception may have copied
      // that exception's text, which can quote a response value, so then only a fixed message is
      // used; the cause chain keeps exception types and stack traces only.
      String text = e.getCause() == null ? e.getMessage() : "Invalid KMIP response";
      throw new ProtocolException(text, response, DecodeException.redact(e));
    } catch (RuntimeException e) {
      throw new ProtocolException("Invalid KMIP response", response, DecodeException.redact(e));
    }
  }

  /**
   * Sends Discover Versions and returns the versions the server offers that this SDK supports.
   *
   * @return the versions, in the server's order
   * @throws IOException for a transport or protocol problem
   */
  public List<ProtocolVersion> discoverVersions() throws IOException {
    return discoverVersions(CallContext.NONE);
  }

  /**
   * {@link #discoverVersions()} bounded by a per-call deadline and cancellation.
   *
   * @param context the deadline and cancellation of this call
   * @return the versions, in the server's order
   * @throws IOException for a transport or protocol problem
   */
  public List<ProtocolVersion> discoverVersions(CallContext context) throws IOException {
    Result result = call(Requests.discoverVersions().build(), context);
    return field(
        result,
        r ->
            r.payload().orElse(structure(RESPONSE_PAYLOAD)).children(PROTOCOL_VERSION).stream()
                .filter(
                    v ->
                        java.util.Arrays.stream(ProtocolVersion.values())
                            .anyMatch(
                                p ->
                                    p.major() == v.require(PROTOCOL_VERSION_MAJOR).intValue()
                                        && p.minor()
                                            == v.require(PROTOCOL_VERSION_MINOR).intValue()))
                .map(
                    v ->
                        ProtocolVersion.of(
                            v.require(PROTOCOL_VERSION_MAJOR).intValue(),
                            v.require(PROTOCOL_VERSION_MINOR).intValue()))
                .toList());
  }

  /**
   * Reads a required field of a successful result. A server that answered Success without it is
   * nonconformant; that is reported as a {@link ProtocolException} carrying the batch item, so
   * every {@code throws IOException} method keeps unchecked exceptions for operation failures
   * only.
   */
  private static <T> T field(Result result, java.util.function.Function<Result, T> reader)
      throws ProtocolException {
    try {
      return reader.apply(result);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed " + result.operation() + " response: " + e.getMessage(),
          result.batchItem(),
          e);
    }
  }

  /**
   * Returns a non-owning view at the highest version both sides support, up to this client's
   * version. Closing the view does not close the transport; this client remains its owner. Prefer
   * {@link #negotiated(KmipTransport, VersionPolicy)}, which returns the sole owner.
   *
   * @return the view
   * @throws IOException as for {@link #negotiated(KmipTransport, VersionPolicy)}; the transport
   *     stays open
   */
  public KmipClient negotiate() throws IOException {
    return negotiate(VersionPolicy.between(ProtocolVersion.V1_1, version));
  }

  /**
   * A non-owning view at the highest version {@code policy} accepts; see {@link #negotiate()}.
   *
   * @param policy the versions to accept
   * @return the view
   * @throws IOException as for {@link #negotiate()}
   */
  public KmipClient negotiate(VersionPolicy policy) throws IOException {
    ProtocolVersion chosen =
        choose(transport, policy, options, knownExtensions, maximumBatchItems, CallContext.NONE);
    return new KmipClient(transport, chosen, options, knownExtensions, maximumBatchItems, false);
  }

  /**
   * A non-owning view of this client at the same version: closing it leaves the transport open,
   * and it stops working when the owner is closed.
   *
   * @return the view
   */
  public KmipClient view() {
    return new KmipClient(transport, version, options, knownExtensions, maximumBatchItems, false);
  }

  /**
   * Whether {@link #close()} closes the transport: true for a client from a constructor or {@code
   * negotiated}, false for a view from {@link #negotiate()} or {@link #view()}.
   *
   * @return whether this client owns the transport
   */
  public boolean ownsTransport() {
    return owner;
  }

  /**
   * Creates a symmetric key and returns its identifier. Fails as {@link #call(Request)} does.
   *
   * @param algorithm the Cryptographic Algorithm, for example AES
   * @param bits the Cryptographic Length
   * @param usage the Cryptographic Usage Mask flags; at least one
   * @return the new key's Unique Identifier
   * @throws IOException for a transport or protocol problem, also a Success without an identifier
   */
  public String createSymmetricKey(
      Enums.CryptographicAlgorithm algorithm, int bits, Enums.CryptographicUsageMask... usage)
      throws IOException {
    return field(
        call(Requests.createSymmetricKey(algorithm, bits, usage)), Result::uniqueIdentifier);
  }

  /**
   * Registers a managed object and returns its identifier. Fails as {@link #call(Request)} does.
   *
   * @param managedObject the object, built with {@link ManagedObjects}
   * @param attributes its attributes, built with {@link Attributes}
   * @return the new object's Unique Identifier
   * @throws IOException for a transport or protocol problem, also a Success without an identifier
   */
  public String register(Ttlv managedObject, Ttlv... attributes) throws IOException {
    return field(
        call(Requests.registerObject(managedObject, attributes)), Result::uniqueIdentifier);
  }

  /**
   * Gets the object {@code id}. Read it from {@link Result#requirePayload()}. Fails as {@link
   * #call(Request)} does.
   *
   * @param id the Unique Identifier
   * @return the successful result
   * @throws IOException for a transport or protocol problem
   */
  public Result get(String id) throws IOException {
    return call(Requests.get().uniqueIdentifier(id).build());
  }

  /**
   * Activates the object {@code id}. Fails as {@link #call(Request)} does.
   *
   * @param id the Unique Identifier
   * @return the successful result
   * @throws IOException for a transport or protocol problem
   */
  public Result activate(String id) throws IOException {
    return call(Requests.activate().uniqueIdentifier(id).build());
  }

  /**
   * Revokes the object {@code id}. Fails as {@link #call(Request)} does.
   *
   * @param id the Unique Identifier
   * @param reason the Revocation Reason Code
   * @param message the Revocation Message; null to send none
   * @return the successful result
   * @throws IOException for a transport or protocol problem
   */
  public Result revoke(String id, Enums.RevocationReasonCode reason, String message)
      throws IOException {
    return call(Requests.revoke(id, reason, message));
  }

  /**
   * Destroys the object {@code id}. Fails as {@link #call(Request)} does.
   *
   * @param id the Unique Identifier
   * @return the successful result
   * @throws IOException for a transport or protocol problem
   */
  public Result destroy(String id) throws IOException {
    return call(Requests.destroy().uniqueIdentifier(id).build());
  }

  /**
   * Polls an asynchronous operation. A completed operation may be answered with Operation Poll or
   * with the original operation (KMIP 2.1 §6.1.38); both are returned. Like {@link
   * #execute(Request)}, a failure is returned, not thrown.
   *
   * @param correlation the Asynchronous Correlation Value of the pending result
   * @return the result
   * @throws IOException for a transport or protocol problem
   */
  public Result poll(byte[] correlation) throws IOException {
    return execute(Requests.poll().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, correlation)).build());
  }

  /**
   * Polls an asynchronous {@code original} operation and rejects a response that names any
   * operation other than Poll or {@code original}. A failure is returned, not thrown.
   *
   * @param correlation the Asynchronous Correlation Value of the pending result
   * @param original the operation that was pending
   * @return the result
   * @throws ProtocolException if the response names another operation
   * @throws IOException for a transport or protocol problem
   */
  public Result poll(byte[] correlation, Operation original) throws IOException {
    Objects.requireNonNull(original, "original operation");
    Response response =
        batch(
            List.of(
                Requests.poll().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, correlation)).build()));
    Result result = response.results().get(0);
    // Compare raw codes: an unknown or vendor operation has no constant (operation() is null) but
    // is still not the polled operation.
    OptionalInt code = result.operationCode();
    if (code.isPresent()
        && code.getAsInt() != Operation.POLL.code()
        && code.getAsInt() != original.code())
      throw new ProtocolException("Poll response operation mismatch", response.message(), null);
    return result;
  }

  /**
   * Cancels a pending asynchronous operation. Like {@link #execute(Request)}, a failure is
   * returned, not thrown.
   *
   * @param correlation the Asynchronous Correlation Value of the pending result
   * @return the result
   * @throws IOException for a transport or protocol problem
   */
  public Result cancel(byte[] correlation) throws IOException {
    return execute(
        Requests.cancel().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, correlation)).build());
  }

  /**
   * Every identifier matching {@code query}, fetched {@code pageSize} at a time with Maximum Items
   * and Offset Items (KMIP 1.3+). Maximum Items is only an upper bound, so a short page does not
   * end the listing: paging continues from the number of identifiers received until a page is
   * empty or the server's Located Items total has been collected. A page larger than requested
   * (the server ignored Maximum Items) is taken as complete. The pages are separate requests, so
   * objects created or destroyed meanwhile can be skipped or repeated. A failed page throws as
   * {@link #call(Request)} does.
   *
   * @param query the filters to match
   * @param pageSize the Maximum Items of each page, at least 1
   * @return the identifiers, without duplicates, in the order received
   * @throws ProtocolException when a page brings nothing new (the server ignores Offset Items)
   *     and more matches may exist: the page was full and Located Items was not sent, or Located
   *     Items counts more than were returned
   * @throws IOException for a transport or protocol problem
   */
  public List<String> locateAll(LocateRequest query, int pageSize) throws IOException {
    if (pageSize < 1) throw new IllegalArgumentException("Invalid page size");
    Set<String> all = new LinkedHashSet<>();
    Integer total = null;
    for (long offset = 0; ; ) {
      Result result = call(query.page((int) Math.min(offset, Integer.MAX_VALUE), pageSize));
      LocateRequest.Page page = LocateRequest.result(result);
      List<String> ids = page.identifiers();
      if (page.locatedItems() != null) total = page.locatedItems();
      boolean added = false;
      for (String id : ids) added |= all.add(id);
      if (ids.isEmpty()) {
        // The end, unless Located Items (this page's, else the last one sent) says more exist.
        if (total != null && all.size() < total)
          throw new ProtocolException(
              "Locate returned an empty page before reaching its Located Items",
              result.batchItem(),
              null);
        return List.copyOf(all);
      }
      if (total != null && all.size() >= total) return List.copyOf(all);
      // A page larger than asked for: the server ignored Maximum Items and returned everything,
      // unless Located Items says there is more.
      if (ids.size() > pageSize) {
        if (total == null) return List.copyOf(all);
        throw new ProtocolException(
            "Locate returned more than Maximum Items but fewer than Located Items",
            result.batchItem(),
            null);
      }
      if (!added) {
        // Without Located Items, a repeated short page holds every match (the server ignores
        // Offset Items, but nothing is missing); a repeated full page means more may exist that
        // paging cannot reach. With Located Items above what was collected, more do exist.
        if (ids.size() < pageSize && total == null) return List.copyOf(all);
        throw new ProtocolException(
            "Locate paging made no progress at offset " + offset, result.batchItem(), null);
      }
      offset += ids.size();
    }
  }

  /**
   * Sends Query for {@code functions}. Fails as {@link #call(Request)} does.
   *
   * @param functions the Query Functions, for example Query Operations
   * @return the successful result
   * @throws IOException for a transport or protocol problem
   */
  public Result query(Enums.QueryFunction... functions) throws IOException {
    return call(
        Requests.query()
            .add(
                Arrays.stream(functions)
                    .map(f -> enumeration(QUERY_FUNCTION, f))
                    .toArray(Ttlv[]::new))
            .build());
  }

  /**
   * Closes the transport if this client owns it ({@link #ownsTransport()}); a view leaves it open.
   *
   * @throws IOException if closing the transport fails
   */
  @Override
  public void close() throws IOException {
    if (owner) transport.close();
  }
}
