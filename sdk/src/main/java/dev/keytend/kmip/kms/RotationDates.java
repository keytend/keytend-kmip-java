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
 * The lifecycle dates a rotation gives the replacement, part of a {@link Rotation} ({@link
 * Rotation#of(RotationDates)}, {@link Rotation#dates(RotationDates)}): what the KMIP Re-key that
 * {@link KeyHandle#rotate(Rotation)}, {@link KeyHandle#rotateOrLatest(Rotation)}, {@link
 * KeyHandle#rotateIfActiveFor(java.time.Duration, Rotation)} and {@link
 * KeyHandle#replaceCompromised(RevocationReason, Rotation)} send asks of the server (KMIP 1.4
 * §4.4, 2.1 §6.1.46). Only the dates a key has are affected: a key with no Deactivation, Protect
 * Stop or Process Start Date rotates the same way with either.
 *
 * <pre>{@code
 * kek.rotateIfActiveFor(Duration.ofDays(60), Rotation.of(RotationDates.SHIFTED));
 * }</pre>
 *
 * @since 0.10.0
 */
public enum RotationDates {
  /**
   * A Re-key without an Offset, the default: on a server that follows KMIP, the replacement gets
   * the old key's Activation, Process Start, Protect Stop and Deactivation Dates as they are, and
   * only its Initial Date is new. A Deactivation Date that a server policy set on the first key is
   * then every replacement's too, so the lineage stops at that date: once it has passed, the current
   * key is Deactivated and rotation refuses it.
   */
  COPIED,

  /**
   * A Re-key with an Offset of 0: the server activates the replacement now and moves the old key's
   * Process Start, Protect Stop and Deactivation Dates by as much as its Activation Date moved
   * (DT2 = DT1 + (AT2 - AT1)). So the replacement keeps the old key's cryptoperiod, counted from
   * now: a key under a policy that sets a Deactivation Date 90 days after activation gives each
   * replacement 90 days of its own. Rotate before the Deactivation Date: a key past it is Deactivated
   * and refused, as with {@link #COPIED}. A server that does not support an Offset refuses the
   * Re-key; a key with one of those dates and no Activation Date cannot be shifted, and servers
   * refuse it (keytend-kmip-server: Illegal Operation or Wrong Key Lifecycle State).
   */
  SHIFTED
}
