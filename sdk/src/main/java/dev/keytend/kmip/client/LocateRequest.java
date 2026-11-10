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
 * A typed, pageable Locate query. Filters are 1.x Attributes, converted to the 2.x Attributes
 * structure when sent at 2.x/3.0. {@link #page(int, int)} adds Maximum Items and Offset Items
 * (Offset Items requires KMIP 1.3), and {@link KmipClient#locateAll} pages through every match.
 *
 * <pre>{@code
 * LocateRequest query = LocateRequest.builder().name("orders-kek")
 *     .state(Enums.State.ACTIVE).build();
 * List<String> ids = LocateRequest.result(client.call(query.toRequest())).identifiers();
 * }</pre>
 *
 * @since 0.10.0
 */
public final class LocateRequest {
  private final List<Ttlv> filters;
  private final Integer storageStatusMask;

  private LocateRequest(List<Ttlv> filters, Integer storageStatusMask) {
    this.filters = List.copyOf(filters);
    this.storageStatusMask = storageStatusMask;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** The request without paging. */
  public Request toRequest() {
    return request(null, null);
  }

  /** One page: at most {@code maximumItems} identifiers starting after {@code offset} matches. */
  public Request page(int offset, int maximumItems) {
    if (offset < 0 || maximumItems < 1) throw new IllegalArgumentException("Invalid page");
    return request(offset == 0 ? null : offset, maximumItems);
  }

  private Request request(Integer offset, Integer maximum) {
    Request.Builder b = Requests.locate();
    if (maximum != null) b.add(integer(MAXIMUM_ITEMS, maximum));
    if (offset != null) b.add(integer(OFFSET_ITEMS, offset));
    if (storageStatusMask != null) b.add(integer(STORAGE_STATUS_MASK, storageStatusMask));
    for (Ttlv f : filters) b.add(f);
    return b.build();
  }

  /** Filter setters. Each adds one 1.x Attribute filter. */
  public static final class Builder {
    private final List<Ttlv> filters = new ArrayList<>();
    private Integer storageStatusMask;

    /** A builder with no filters, as {@link LocateRequest#builder()} returns. */
    public Builder() {}

    public Builder name(String name) {
      return attribute(Attributes.name(name));
    }

    public Builder objectType(Enums.ObjectType type) {
      return attribute(Attributes.attribute("Object Type", enumeration(OBJECT_TYPE, type)));
    }

    public Builder state(Enums.State state) {
      return attribute(Attributes.attribute("State", enumeration(STATE, state)));
    }

    public Builder algorithm(Enums.CryptographicAlgorithm algorithm) {
      return attribute(Attributes.algorithm(algorithm));
    }

    public Builder objectGroup(String group) {
      return attribute(Attributes.attribute("Object Group", text(OBJECT_GROUP, group)));
    }

    /** Include archived objects as well as on-line ones (Storage Status Mask). */
    public Builder storageStatus(Enums.StorageStatusMask... statuses) {
      storageStatusMask = Attributes.mask(statuses);
      return this;
    }

    /** Any 1.x Attribute filter. */
    public Builder attribute(Ttlv attribute) {
      if (attribute.tag() != ATTRIBUTE.code())
        throw new IllegalArgumentException("Expected Attribute");
      filters.add(attribute);
      return this;
    }

    public LocateRequest build() {
      return new LocateRequest(filters, storageStatusMask);
    }
  }

  /** The identifiers of one Locate response, and Located Items when the server sent it. */
  public record Page(List<String> identifiers, Integer locatedItems) {
    public Page {
      identifiers = List.copyOf(identifiers);
    }
  }

  /**
   * @throws KmipException when the result is not Success
   * @throws ProtocolException for a malformed payload
   */
  public static Page result(Result result) throws ProtocolException {
    result.requireSuccess();
    try {
      Ttlv p = result.payload().orElse(structure(RESPONSE_PAYLOAD));
      List<String> ids = new ArrayList<>();
      for (Ttlv id : p.children(UNIQUE_IDENTIFIER)) ids.add(id.textValue());
      return new Page(ids, p.child(LOCATED_ITEMS).map(Ttlv::intValue).orElse(null));
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed Locate response: " + e.getMessage(), result.batchItem(), e);
    }
  }
}
