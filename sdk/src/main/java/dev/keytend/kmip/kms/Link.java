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

import java.util.Objects;

/**
 * A link from one managed object to another, such as {@link LinkKind#REPLACEMENT} or {@link
 * LinkKind#PUBLIC_KEY}. Read from the 1.x/2.x Link structure and from 3.0's per-type link
 * attributes alike.
 *
 * @param kind the link kind ({@link LinkKind#OTHER} for a vendor or unknown type)
 * @param rawType the KMIP Link Type code
 * @param targetId the linked object's identifier
 * @since 0.10.0
 */
public record Link(LinkKind kind, int rawType, String targetId) {
  /**
   * Checks the components.
   *
   * @param kind the link kind
   * @param rawType the KMIP Link Type code
   * @param targetId the linked object's identifier
   * @throws NullPointerException when {@code kind} or {@code targetId} is null
   */
  public Link {
    Objects.requireNonNull(kind, "kind");
    Objects.requireNonNull(targetId, "targetId");
  }
}
