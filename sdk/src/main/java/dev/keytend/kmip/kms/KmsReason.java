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

import dev.keytend.kmip.model.Enums;

/**
 * The reason a server gave for a failure result, as returned by {@link KmsException#serverReason()}:
 * the common KMIP Result Reasons an application may want to tell apart, without importing the
 * protocol layer.
 *
 * <p>A reason is the server's word, not the SDK's verdict. Each constant names one KMIP Result
 * Reason, or several that the specification uses for the same refusal (codes later versions added
 * for it, or reasons with the same remedy); each constant lists them. A server's choice of
 * reason is not corrected: for example, KMIP 1.x servers refuse to use a key whose state forbids
 * the operation (a Pre-Active key, say) with Permission Denied or Illegal Operation, which are
 * {@link #PERMISSION_DENIED} and {@link #ILLEGAL_OPERATION} here while the exception is a {@link
 * StateConflictException}, where KMIP 2.0 says Wrong Key Lifecycle State ({@link
 * #WRONG_LIFECYCLE_STATE}). To decide what to do, use {@link KmsException#category()} and the
 * subtype, which are the same for the same failure on every version; use the reason to tell cases
 * apart within them, or to log.
 *
 * <p>Every other reason, including reasons this enum does not name and vendor codes, is {@link
 * #OTHER}; {@link KmsException#reasonCode()} has the code. Later releases may add constants, so a
 * code that is {@code OTHER} now may then map to a new constant: code that switches over this enum
 * should keep a {@code default} branch.
 *
 * @since 0.10.0
 */
public enum KmsReason {
  /**
   * The object does not exist: Item Not Found, or Object Not Found (KMIP 2.0 and later). A
   * destroyed object is {@link #OBJECT_DESTROYED} where the server says so (KMIP 2.0 and later);
   * {@link KmsException.Category#NOT_FOUND} covers both.
   */
  NOT_FOUND,
  /** The object was destroyed: Object Destroyed (KMIP 2.0 and later). */
  OBJECT_DESTROYED,
  /** The object is archived and must be recovered first: Object Archived. */
  OBJECT_ARCHIVED,
  /**
   * The client is authenticated but not allowed to do this: Permission Denied, or Not Authorised
   * (KMIP 2.0 and later). KMIP 1.x servers also give Permission Denied for some state refusals
   * (see above).
   */
  PERMISSION_DENIED,
  /**
   * The server did not accept the client's credentials: Authentication Not Successful, or Bad
   * Password (KMIP 2.0 and later).
   */
  AUTHENTICATION_FAILED,
  /**
   * The server will not release the object's key material: Sensitive, or Not Extractable (both
   * KMIP 1.4 and later).
   */
  NOT_EXTRACTABLE,
  /**
   * The object's lifecycle state forbids the operation: Wrong Key Lifecycle State (KMIP 2.0 and
   * later). KMIP 1.x servers refuse such operations with {@link #ILLEGAL_OPERATION} or {@link
   * #PERMISSION_DENIED}; the exception is a {@link StateConflictException} either way.
   */
  WRONG_LIFECYCLE_STATE,
  /**
   * The server will not perform the operation on this object: Illegal Operation (KMIP 1.x;
   * reserved from 2.0). KMIP 1.x servers use it for a lifecycle state that forbids the operation
   * (what 2.0 calls Wrong Key Lifecycle State) and for other refusals of the object; the
   * exception's {@link KmsException#category()} says which the SDK took it for.
   */
  ILLEGAL_OPERATION,
  /**
   * An object with that name or identity already exists: Object Already Exists (KMIP 1.4 and
   * later), or Non Unique Name Attribute (KMIP 2.0 and later). Before KMIP 1.4, neither is defined;
   * servers there answer with another reason, such as Illegal Operation or Invalid Field.
   */
  ALREADY_EXISTS,
  /** The server could not parse or accept the request message: Invalid Message. */
  INVALID_MESSAGE,
  /** A field of the request has an invalid value: Invalid Field. */
  INVALID_FIELD,
  /** A required field of the request is missing: Missing Data. */
  MISSING_DATA,
  /** The server does not support the operation: Operation Not Supported. */
  OPERATION_NOT_SUPPORTED,
  /** The server does not support a feature the request uses: Feature Not Supported. */
  FEATURE_NOT_SUPPORTED,
  /**
   * A cryptographic operation failed, for example an authentication tag did not verify:
   * Cryptographic Failure.
   */
  CRYPTOGRAPHIC_FAILURE,
  /**
   * The server is overloaded or its key storage is unavailable: Server Limit Exceeded, Protection
   * Storage Unavailable, Private Protection Storage Unavailable, or Public Protection Storage
   * Unavailable (all KMIP 2.0 and later). A read refused this way is a {@link TransientException};
   * a mutation, which is never re-sent, is a {@link ServerFailureException}.
   */
  SERVER_BUSY,
  /**
   * The object's usage limits are used up (a quota, not a failure of the server or of the
   * request): Usage Limit Exceeded (KMIP 2.0 and later). A {@link StateConflictException}. Not
   * every operation over budget arrives so: the KMIP 2.x text of Encrypt and Sign (2.1 §6.1.17,
   * §6.1.55) prescribes Permission Denied, so a seal or a signature over its budget is {@link
   * #PERMISSION_DENIED} (FIX_ACCESS) on a conforming server, as are 1.x refusals, which have no
   * such reason; MAC answers Usage Limit Exceeded.
   */
  USAGE_LIMIT_EXCEEDED,
  /** The server failed: General Failure, or Internal Server Error (KMIP 2.0 and later). */
  SERVER_ERROR,
  /** Any other reason, including a reason this enum does not name and a vendor code. */
  OTHER;

  /** The constant for a Result Reason code; {@link #OTHER} for every code not named above. */
  static KmsReason of(int code) {
    return Enums.ResultReason.fromCode(code).map(KmsReason::of).orElse(OTHER);
  }

  /** A switch with no default, so that a new protocol reason must be mapped before this compiles. */
  static KmsReason of(Enums.ResultReason reason) {
    return switch (reason) {
      case ITEM_NOT_FOUND, OBJECT_NOT_FOUND -> NOT_FOUND;
      case OBJECT_DESTROYED -> OBJECT_DESTROYED;
      case OBJECT_ARCHIVED -> OBJECT_ARCHIVED;
      case PERMISSION_DENIED, NOT_AUTHORISED -> PERMISSION_DENIED;
      case AUTHENTICATION_NOT_SUCCESSFUL, BAD_PASSWORD -> AUTHENTICATION_FAILED;
      case SENSITIVE, NOT_EXTRACTABLE -> NOT_EXTRACTABLE;
      case WRONG_KEY_LIFECYCLE_STATE -> WRONG_LIFECYCLE_STATE;
      case ILLEGAL_OPERATION -> ILLEGAL_OPERATION;
      case OBJECT_ALREADY_EXISTS, NON_UNIQUE_NAME_ATTRIBUTE -> ALREADY_EXISTS;
      case INVALID_MESSAGE -> INVALID_MESSAGE;
      case INVALID_FIELD -> INVALID_FIELD;
      case MISSING_DATA -> MISSING_DATA;
      case OPERATION_NOT_SUPPORTED -> OPERATION_NOT_SUPPORTED;
      case FEATURE_NOT_SUPPORTED -> FEATURE_NOT_SUPPORTED;
      case CRYPTOGRAPHIC_FAILURE -> CRYPTOGRAPHIC_FAILURE;
      case SERVER_LIMIT_EXCEEDED,
          PROTECTION_STORAGE_UNAVAILABLE,
          PRIVATE_PROTECTION_STORAGE_UNAVAILABLE,
          PUBLIC_PROTECTION_STORAGE_UNAVAILABLE ->
          SERVER_BUSY;
      case USAGE_LIMIT_EXCEEDED -> USAGE_LIMIT_EXCEEDED;
      case GENERAL_FAILURE, INTERNAL_SERVER_ERROR -> SERVER_ERROR;
      case RESPONSE_TOO_LARGE,
          OPERATION_CANCELED_BY_REQUESTER,
          INDEX_OUT_OF_BOUNDS,
          APPLICATION_NAMESPACE_NOT_SUPPORTED,
          KEY_FORMAT_TYPE_NOT_SUPPORTED,
          KEY_COMPRESSION_TYPE_NOT_SUPPORTED,
          ENCODING_OPTION_ERROR,
          KEY_VALUE_NOT_PRESENT,
          ATTESTATION_REQUIRED,
          ATTESTATION_FAILED,
          INVALID_TICKET,
          NUMERIC_RANGE,
          INVALID_DATA_TYPE,
          READ_ONLY_ATTRIBUTE,
          MULTI_VALUED_ATTRIBUTE,
          UNSUPPORTED_ATTRIBUTE,
          ATTRIBUTE_INSTANCE_NOT_FOUND,
          ATTRIBUTE_NOT_FOUND,
          ATTRIBUTE_READ_ONLY,
          ATTRIBUTE_SINGLE_VALUED,
          BAD_CRYPTOGRAPHIC_PARAMETERS,
          CODEC_ERROR,
          RESERVED,
          ILLEGAL_OBJECT_TYPE,
          INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK,
          INVALID_ASYNCHRONOUS_CORRELATION_VALUE,
          INVALID_ATTRIBUTE,
          INVALID_ATTRIBUTE_VALUE,
          INVALID_CORRELATION_VALUE,
          INVALID_CSR,
          INVALID_OBJECT_TYPE,
          RESERVED_49,
          KEY_WRAP_TYPE_NOT_SUPPORTED,
          RESERVED_51,
          MISSING_INITIALIZATION_VECTOR,
          RESERVED_56,
          UNKNOWN_ENUMERATION,
          UNKNOWN_MESSAGE_EXTENSION,
          UNKNOWN_TAG,
          UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS,
          UNSUPPORTED_PROTOCOL_VERSION,
          WRAPPING_OBJECT_ARCHIVED,
          WRAPPING_OBJECT_DESTROYED,
          WRAPPING_OBJECT_NOT_FOUND,
          PKCS_11_CODEC_ERROR,
          PKCS_11_INVALID_FUNCTION,
          PKCS_11_INVALID_INTERFACE,
          UNKNOWN_OBJECT_GROUP,
          CONSTRAINT_VIOLATION,
          DUPLICATE_PROCESS_REQUEST,
          CIRCULAR_LINK_ERROR ->
          OTHER;
    };
  }
}
