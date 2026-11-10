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

package dev.keytend.kmip.transport;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

/**
 * An exchange failed before any byte of the request was written: the connection, TLS handshake
 * or wait for a pooled connection failed, or the call was canceled, interrupted or past its
 * deadline before sending. The server cannot have received the request, so repeating it, also on
 * another endpoint, is safe even for a mutation. The cause is the original failure (for example
 * {@link java.net.ConnectException}, {@link javax.net.ssl.SSLHandshakeException}, {@link
 * SocketTimeoutException} or {@link InterruptedIOException}).
 *
 * <p>A {@link CallContext} deadline or cancellation that takes effect before sending is reported
 * here, with a {@link SocketTimeoutException} or {@link InterruptedIOException} cause, rather than
 * as that type itself: test with {@link #timedOut()} and {@link #cancelled()}. Once the request may
 * have been written the transports throw {@code SocketTimeoutException} and {@code
 * InterruptedIOException} directly, and the outcome of a mutation is unknown.
 *
 * @since 0.10.0
 */
public final class RequestNotSentException extends IOException {
  private final boolean local;

  /** A failure to reach the server (connect, TLS handshake). */
  public RequestNotSentException(String message, Throwable cause) {
    this(message, cause, false);
  }

  /**
   * @param local true when the cause is on the client side (the transport was closed, the call was
   *     canceled or its deadline passed while waiting for a connection or lock), so the server
   *     itself may be healthy
   */
  public RequestNotSentException(String message, Throwable cause, boolean local) {
    super(message, cause);
    this.local = local;
  }

  /** True when the request was held back on the client side rather than refused by the network. */
  public boolean local() {
    return local;
  }

  /**
   * True when the cause is a {@link SocketTimeoutException}: the call's deadline passed, or the
   * connect, handshake or wait for a pooled connection or the exchange lock timed out.
   */
  public boolean timedOut() {
    return getCause() instanceof SocketTimeoutException;
  }

  /**
   * True when the cause is an {@link InterruptedIOException} other than a timeout: the {@link
   * CallContext} was canceled or the calling thread interrupted before the request was sent.
   */
  public boolean cancelled() {
    return getCause() instanceof InterruptedIOException && !timedOut();
  }
}
