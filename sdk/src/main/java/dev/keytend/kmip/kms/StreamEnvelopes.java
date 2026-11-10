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

package dev.keytend.kmip.kms;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Streaming sealed data ({@link KeyHandle#sealing}, {@link KeyHandle#opening}): the STREAM
 * construction of Hoang, Reyhanitabar, Rogaway and Vizár (CRYPTO 2015) over AES-256-GCM, under a
 * fresh data key per stream that the key-encryption key wraps on the server:
 *
 * <pre>
 * header: "KTS" (3 bytes) | version 0x01 | u16 wrapped-key length w (1..65535)
 *   | w bytes: the wrapped data key, a {@link Ciphertext} in its stored format
 *   | u32 chunk size c (4 KiB..1 MiB) | 7-byte nonce prefix
 * chunks: AES-GCM(chunk i) followed by its 16-byte tag, for i = 0, 1, ...; every chunk but the last
 *   holds exactly c plaintext bytes, the last 0..c (0 only when it is chunk 0)
 * </pre>
 *
 * The nonce of chunk i is prefix || u32 i || 0x00, or 0x01 for the last chunk; the additional data
 * of every chunk is the whole header followed by the caller's. The reader decides which chunk is
 * the last from where the input ends, never from the data, so a cut, an extension, a dropped or a
 * moved chunk changes a nonce or the bytes of a chunk and fails its tag. At most 2^32 chunks.
 */
final class StreamEnvelopes {
  private static final byte[] MAGIC = {'K', 'T', 'S'};
  private static final byte VERSION = 1;
  private static final int PREFIX = 7, TAG = 16, KEY_BITS = 256;

  /** The chunk size the writer uses. */
  static final int CHUNK = 64 * 1024;

  /** The chunk sizes a reader accepts. */
  static final int MIN_CHUNK = 4 * 1024, MAX_CHUNK = 1024 * 1024;

  /** The most chunks a stream may have: the nonce holds a 32-bit counter. */
  static final long MAX_CHUNKS = 1L << 32;

  private static final SecureRandom RANDOM = new SecureRandom();

  private StreamEnvelopes() {}

  /** A parsed header. */
  record Header(byte[] bytes, Ciphertext wrappedKey, int chunkSize, byte[] prefix) {}

  /**
   * A sealing stream under a fresh data key from {@code kek} (one Encrypt request, now), writing
   * chunks of {@code chunkSize} plaintext bytes (any positive size: tests write sizes the reader
   * refuses) and refusing to write more than {@code maxChunks} chunks. Nothing is written to {@code
   * out} before this returns (the header goes out with the first chunk), and {@code out} is closed
   * when this throws.
   */
  static SealingStream sealing(
      KeyHandle kek, OutputStream out, byte[] aad, int chunkSize, long maxChunks) {
    Objects.requireNonNull(out, "out");
    try {
      return sealingLeavingOpen(kek, out, aad, chunkSize, maxChunks);
    } catch (Throwable e) {
      closing(out, e);
      throw e;
    }
  }

  /**
   * {@link #sealing}, leaving {@code out} open, and untouched, when this throws: {@link
   * CurrentKey#sealing} repeats it under a newer key after a refusal, then closes {@code out} itself
   * when it fails.
   */
  static SealingStream sealingLeavingOpen(
      KeyHandle kek, OutputStream out, byte[] aad, int chunkSize, long maxChunks) {
    Objects.requireNonNull(out, "out");
    if (chunkSize < 1) throw new IllegalArgumentException("chunkSize");
    return writer(kek, out, aad, chunkSize, maxChunks);
  }

  private static SealingStream writer(
      KeyHandle kek, OutputStream out, byte[] aad, int chunkSize, long maxChunks) {
    byte[] boundAad = aad == null ? new byte[0] : aad.clone();
    DataKey dek = Kms.named("seal", () -> kek.generateDataKey(KEY_BITS, aad));
    try {
      byte[] wrapped = dek.wrapped().toBytes();
      if (wrapped.length > 0xffff)
        throw new IllegalArgumentException("The key identifier is too long for a sealed stream");
      byte[] prefix = new byte[PREFIX];
      RANDOM.nextBytes(prefix);
      byte[] header =
          ByteBuffer.allocate(MAGIC.length + 1 + 2 + wrapped.length + 4 + PREFIX)
              .put(MAGIC)
              .put(VERSION)
              .putShort((short) wrapped.length)
              .put(wrapped)
              .putInt(chunkSize)
              .put(prefix)
              .array();
      return new Writer(out, dek, kek.id(), header, prefix, boundAad, chunkSize, maxChunks);
    } catch (RuntimeException e) {
      dek.destroy();
      throw e;
    }
  }

  /**
   * An opening stream: reads and checks the header from {@code in}, then {@code unwrap} recovers the
   * data key (with the key and state rules of the caller's entry point), now; the chunks are
   * decrypted as they are read. {@code in} is closed when this throws.
   */
  static InputStream opening(
      InputStream in, byte[] aad, Function<Ciphertext, DestroyableSecretKey> unwrap, long maxChunks)
      throws IOException {
    Objects.requireNonNull(in, "in");
    try {
      byte[] boundAad = aad == null ? new byte[0] : aad.clone();
      Header header = readHeader(in);
      DestroyableSecretKey dek = Kms.named("open", () -> unwrap.apply(header.wrappedKey()));
      try {
        return new Reader(in, dek, header, boundAad, maxChunks);
      } catch (RuntimeException e) {
        dek.destroy();
        throw e;
      }
    } catch (Throwable e) {
      closing(in, e);
      throw e;
    }
  }

  /**
   * Closes {@code stream}, which a sealing or opening stream was to own, because the method making
   * it fails with {@code failure}; an error closing it is added to {@code failure} as suppressed.
   */
  static void closing(Closeable stream, Throwable failure) {
    try {
      stream.close();
    } catch (Throwable e) {
      if (e != failure) failure.addSuppressed(e);
    }
  }

  /**
   * Reads a header from {@code in} (and nothing after it), checking every field.
   *
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} for anything else
   */
  static Header readHeader(InputStream in) throws IOException {
    Objects.requireNonNull(in, "in");
    byte[] start = readFully(in, MAGIC.length + 1 + 2);
    if (!Arrays.equals(Arrays.copyOf(start, MAGIC.length), MAGIC))
      throw invalid("is not a sealed stream", null);
    if (start[MAGIC.length] != VERSION) throw invalid("has an unknown format version", null);
    int w = Short.toUnsignedInt(ByteBuffer.wrap(start, MAGIC.length + 1, 2).getShort());
    if (w == 0) throw invalid("has a bad wrapped-key length", null);
    byte[] wrapped = readFully(in, w);
    byte[] end = readFully(in, 4 + PREFIX);
    long chunkSize = Integer.toUnsignedLong(ByteBuffer.wrap(end).getInt());
    if (chunkSize < MIN_CHUNK || chunkSize > MAX_CHUNK)
      throw invalid(
          "has a chunk size of " + chunkSize + " bytes, outside " + MIN_CHUNK + ".." + MAX_CHUNK,
          null);
    Ciphertext key;
    try {
      key = Ciphertext.fromBytes(wrapped);
    } catch (CryptographicFailureException e) {
      throw invalid("holds a malformed wrapped key", null);
    }
    byte[] bytes =
        ByteBuffer.allocate(start.length + w + end.length).put(start).put(wrapped).put(end).array();
    return new Header(bytes, key, (int) chunkSize, Arrays.copyOfRange(end, 4, 4 + PREFIX));
  }

  private static byte[] readFully(InputStream in, int n) throws IOException {
    byte[] b = in.readNBytes(n);
    if (b.length != n) throw invalid("is truncated", null);
    return b;
  }

  /** The nonce of chunk {@code index}: prefix || u32 index || final flag. */
  static byte[] nonce(byte[] prefix, long index, boolean last) {
    return ByteBuffer.allocate(PREFIX + 4 + 1)
        .put(prefix)
        .putInt((int) index)
        .put((byte) (last ? 1 : 0))
        .array();
  }

  private static Cipher cipher(String operation) {
    try {
      return Cipher.getInstance("AES/GCM/NoPadding");
    } catch (GeneralSecurityException e) {
      throw failure("AES-GCM is not available: " + e.getClass().getSimpleName(), operation, null);
    }
  }

  private static CryptographicFailureException invalid(String why, String keyId) {
    return new CryptographicFailureException(
        "open: the sealed stream " + why,
        null,
        // opening's name while it reads the header; "open" when a read finds a chunk invalid
        Kms.named("open"),
        keyId,
        null,
        null,
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT);
  }

  private static CryptographicFailureException failure(String why, String operation, String keyId) {
    return new CryptographicFailureException(
        operation + ": local AES-GCM failed: " + why,
        null,
        operation,
        keyId,
        null,
        null,
        CryptographicFailureException.Kind.OTHER);
  }

  /** The sealing stream. Not thread-safe. */
  private static final class Writer extends SealingStream {
    private final OutputStream out;
    private final DataKey dek;
    private final String keyId;
    private final byte[] header, prefix, aad;
    private final long maxChunks;
    private final Cipher cipher = cipher("seal");
    private final byte[] plain, sealed;
    private int filled;
    private long index;
    private boolean headerWritten, finished, closed;

    /** Set once a write failed: the output is broken, and nothing may complete it. */
    private boolean failed;

    Writer(
        OutputStream out,
        DataKey dek,
        String keyId,
        byte[] header,
        byte[] prefix,
        byte[] aad,
        int chunkSize,
        long maxChunks) {
      this.out = out;
      this.dek = dek;
      this.keyId = keyId;
      this.header = header;
      this.prefix = prefix;
      this.aad = aad;
      this.maxChunks = maxChunks;
      this.plain = new byte[chunkSize];
      this.sealed = new byte[chunkSize + TAG];
    }

    @Override
    public void write(int b) throws IOException {
      open();
      if (filled == plain.length) emit(false);
      plain[filled++] = (byte) b;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      Objects.checkFromIndexSize(off, len, b.length);
      open();
      while (len > 0) {
        if (filled == plain.length) emit(false);
        int n = Math.min(len, plain.length - filled);
        System.arraycopy(b, off, plain, filled, n);
        filled += n;
        off += n;
        len -= n;
      }
    }

    /** Flushes the underlying stream; up to one chunk of plaintext stays buffered until it fills. */
    @Override
    public void flush() throws IOException {
      if (closed) return;
      if (!finished) open();
      out.flush();
    }

    @Override
    public void finish() throws IOException {
      if (finished) return;
      open();
      emit(true);
      try {
        out.flush();
      } catch (IOException e) {
        failed = true;
        throw e;
      } finally {
        end();
      }
      finished = true;
    }

    @Override
    public void close() throws IOException {
      if (closed) return;
      closed = true;
      IOException incomplete =
          finished
              ? null
              : new IOException(
                  failed
                      ? "seal: the sealing stream failed earlier, so its output is incomplete and cannot be opened;"
                          + " discard it"
                      : "seal: the sealing stream was closed without finish(), so its output has no end and cannot"
                          + " be opened; discard it (call finish() once everything is written)");
      try {
        out.close();
      } catch (IOException e) {
        if (incomplete == null) throw e;
        incomplete.addSuppressed(e);
      } finally {
        end();
      }
      if (incomplete != null) throw incomplete;
    }

    private void open() throws IOException {
      if (closed) throw new IOException("seal: the sealing stream is closed");
      if (failed)
        throw new IOException("seal: the sealing stream failed earlier; its output is incomplete");
      if (finished)
        throw new IOException("seal: the sealing stream is finished; write before finish()");
    }

    /** Encrypts and writes the buffered chunk; marks the stream failed if anything goes wrong. */
    private void emit(boolean last) throws IOException {
      boolean ok = false;
      try {
        if (!last && index + 1 >= maxChunks)
          throw new IOException(
              "seal: the stream is longer than a sealed stream may be ("
                  + maxChunks
                  + " chunks of "
                  + plain.length
                  + " bytes); split the data");
        int n;
        try {
          cipher.init(
              Cipher.ENCRYPT_MODE,
              dek.key(),
              new GCMParameterSpec(TAG * 8, nonce(prefix, index, last)));
          cipher.updateAAD(header);
          cipher.updateAAD(aad);
          n = cipher.doFinal(plain, 0, filled, sealed, 0);
        } catch (GeneralSecurityException e) {
          throw failure(e.getClass().getSimpleName(), "seal", keyId);
        }
        if (!headerWritten) {
          out.write(header);
          headerWritten = true;
        }
        out.write(sealed, 0, n);
        index++;
        filled = 0;
        ok = true;
      } finally {
        if (!ok) {
          failed = true;
          end();
        }
      }
    }

    /** Destroys the data key and wipes the buffers (best effort: JCA keeps its own copies). */
    private void end() {
      dek.destroy();
      Arrays.fill(plain, (byte) 0);
      Arrays.fill(sealed, (byte) 0);
      filled = 0;
    }
  }

  /** The opening stream. Not thread-safe. */
  private static final class Reader extends InputStream {
    private final InputStream in;
    private final DestroyableSecretKey dek;
    private final byte[] header, prefix, aad;
    private final String keyId;
    private final long maxChunks;
    private final Cipher cipher = cipher("open");

    /** One sealed chunk and one byte of the next, to tell whether the chunk is the last. */
    private final byte[] sealed;

    private final byte[] plain;
    private int sealedLength, position, limit;
    private long index;
    private boolean last, closed;
    private CryptographicFailureException failure;

    Reader(InputStream in, DestroyableSecretKey dek, Header header, byte[] aad, long maxChunks) {
      this.in = in;
      this.dek = dek;
      this.header = header.bytes();
      this.prefix = header.prefix();
      this.keyId = header.wrappedKey().keyId();
      this.aad = aad;
      this.maxChunks = maxChunks;
      this.sealed = new byte[header.chunkSize() + TAG + 1];
      this.plain = new byte[header.chunkSize()];
    }

    @Override
    public int read() throws IOException {
      if (closed) throw new IOException("open: the opening stream is closed");
      while (position == limit) {
        if (last) return -1;
        next();
      }
      return plain[position++] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      Objects.checkFromIndexSize(off, len, b.length);
      if (closed) throw new IOException("open: the opening stream is closed");
      if (len == 0) return 0;
      while (position == limit) {
        if (last) return -1;
        next();
      }
      int n = Math.min(len, limit - position);
      System.arraycopy(plain, position, b, off, n);
      position += n;
      return n;
    }

    /** The decrypted bytes not yet read; reading more may block for the next chunk. */
    @Override
    public int available() throws IOException {
      if (closed) throw new IOException("open: the opening stream is closed");
      return limit - position;
    }

    /** Closes the underlying stream and destroys the data key; unread data is not checked. */
    @Override
    public void close() throws IOException {
      if (closed) return;
      closed = true;
      try {
        in.close();
      } finally {
        end(true);
      }
    }

    /**
     * Reads the next chunk and one byte after it (a full chunk followed by more is not the last),
     * decrypts it and releases its plaintext only once its tag verified. A read that failed with
     * an IOException can be retried: the bytes read so far are kept.
     */
    private void next() throws IOException {
      if (closed) throw new IOException("open: the opening stream is closed");
      if (failure != null) throw failure;
      int n;
      while (sealedLength < sealed.length
          && (n = in.read(sealed, sealedLength, sealed.length - sealedLength)) >= 0)
        sealedLength += n;
      boolean isLast = sealedLength < sealed.length;
      int length = isLast ? sealedLength : sealed.length - 1;
      try {
        if (isLast ? index >= maxChunks : index + 1 >= maxChunks)
          throw invalid("has more chunks than a sealed stream may have (" + maxChunks + ")", keyId);
        if (length < TAG)
          throw invalid(
              length == 0
                  ? "is truncated: it ends after its header"
                  : "is truncated: its last chunk is shorter than a tag",
              keyId);
        if (isLast && length == TAG && index > 0)
          throw invalid(
              "ends with an empty chunk after a full one, which a writer never does", keyId);
        try {
          cipher.init(
              Cipher.DECRYPT_MODE,
              dek,
              new GCMParameterSpec(TAG * 8, nonce(prefix, index, isLast)));
          cipher.updateAAD(header);
          cipher.updateAAD(aad);
          limit = cipher.doFinal(sealed, 0, length, plain, 0);
        } catch (AEADBadTagException e) {
          throw new CryptographicFailureException(
              "open: chunk "
                  + index
                  + " of the sealed stream did not authenticate (the stream was cut, extended,"
                  + " reordered or changed, or the additional data differs); discard everything read from it",
              null,
              "open",
              keyId,
              null,
              null,
              CryptographicFailureException.Kind.AUTHENTICATION_FAILED);
        } catch (GeneralSecurityException e) {
          throw failure(e.getClass().getSimpleName(), "open", keyId);
        }
      } catch (CryptographicFailureException e) {
        failure = e;
        end(true);
        throw e;
      }
      position = 0;
      index++;
      last = isLast;
      if (isLast) {
        sealedLength = 0;
        end(false);
      } else {
        sealed[0] = sealed[sealed.length - 1];
        sealedLength = 1;
      }
    }

    /**
     * Destroys the data key and wipes the ciphertext buffer, and the plaintext buffer too when
     * {@code wipe} (after the last chunk, its released plaintext stays readable until closed).
     */
    private void end(boolean wipe) {
      dek.destroy();
      Arrays.fill(sealed, (byte) 0);
      if (wipe) {
        Arrays.fill(plain, (byte) 0);
        position = limit = 0;
      }
    }
  }
}
