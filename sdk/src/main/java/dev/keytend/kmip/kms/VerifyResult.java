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

/**
 * The server's verdict on a signature or MAC. A verify call that completes normally can still
 * return {@link #INVALID} or {@link #UNKNOWN}: only {@link #VALID} means the signature is good.
 *
 * @since 0.10.0
 */
public enum VerifyResult {
  /** The server verified the signature or MAC (KMIP Validity Indicator Valid). */
  VALID,
  /** The signature or MAC does not match (KMIP Validity Indicator Invalid). */
  INVALID,
  /** The server could not decide (KMIP Validity Indicator Unknown, or a vendor value). */
  UNKNOWN
}
