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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * {@link KmsKeys#moveName}: one Name value moved between two exact identifiers in one ordered
 * batch with Undo, [Delete Attribute on the source, Add Attribute on the target], never resent
 * and never split into separate requests. Every request shares one call scope; the outcome is
 * settled by reading both objects' names back.
 */
final class NameTransfer {
  static final String OP = "moveName";

  private final Kms kms;
  private final String name, fromId, toId;

  private NameTransfer(Kms kms, String name, String fromId, String toId) {
    this.kms = kms;
    this.name = name;
    this.fromId = fromId;
    this.toId = toId;
  }

  static void move(Kms kms, String name, String fromId, String toId) {
    kms.run(
        OP,
        () -> {
          new NameTransfer(kms, name, fromId, toId).run();
        });
  }

  /** One object's instances of the name, read with one Get Attributes. */
  private record Holding(String id, int count, int legacyIndex) {
    boolean holds() {
      return count > 0;
    }
  }

  /**
   * What one exact-ID read-back observed: a holding, or why there is none (a {@link
   * KmsException}, or the {@link IllegalStateException} of a closed {@code Kms}).
   */
  private record Observed(String id, Holding holding, RuntimeException failure) {
    String describe(String name) {
      if (holding != null) return id + (holding.holds() ? " holds " : " does not hold ") + name;
      if (!(failure instanceof KmsException k)) return id + " unreadable (Kms closed)";
      return id
          + " unreadable ("
          + k.getClass().getSimpleName()
          + k.serverReason().map(r -> ", " + r).orElse("")
          + ")";
    }
  }

  /** How the server answered the batch: both items applied, or one acknowledged refusal. */
  private record Reply(boolean applied, KmsException refusal) {}

  private void run() {
    Holding from = holding(fromId), to = holding(toId);
    if (!from.holds() && to.holds()) return; // already the observed postcondition
    if (from.holds() == to.holds())
      throw new StateConflictException(
              OP
                  + ": "
                  + (from.holds()
                      ? "both " + fromId + " and " + toId + " hold "
                      : "neither " + fromId + " nor " + toId + " holds ")
                  + "the name "
                  + name
                  + "; nothing was changed",
              null,
              OP,
              fromId,
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    if (from.count() > 1)
      throw new StateConflictException(
              OP
                  + ": "
                  + fromId
                  + " holds the name "
                  + name
                  + " "
                  + from.count()
                  + " times; one transfer cannot leave it without the name; nothing was changed",
              null,
              OP,
              fromId,
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    List<Request> batch =
        List.of(
            delete(from),
            Requests.addAttribute()
                .uniqueIdentifier(toId)
                .attribute(Attributes.name(name))
                .build());
    Reply[] reply = new Reply[1];
    KmsException failure;
    try {
      kms.execute(
          OP,
          Kms.Kind.MUTATION,
          fromId,
          s -> {
            Response response =
                s.batch(
                    batch,
                    RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.UNDO));
            reply[0] = reply(response);
            if (!reply[0].applied()) throw reply[0].refusal();
            return null;
          });
      failure = null;
    } catch (OutcomeUnknownException unknown) {
      failure = unknown;
    } catch (KmsException e) {
      // Not sent (no connection, the deadline, a request the version cannot express): definite.
      if (reply[0] == null) throw e;
      failure = e;
    } catch (IllegalStateException closed) {
      // close() raced the batch: its cause says whether it may have been sent. Closed before it
      // was (no cause, or a failure that was not sent), it stays an ordinary closed Kms.
      if (!kms.closed()
          || !(closed.getCause() instanceof KmsException cause)
          || (reply[0] == null && !(cause instanceof OutcomeUnknownException))) throw closed;
      failure = cause;
    }
    // Settled by what both objects hold now, with what is left of the one deadline.
    Observed source = observe(fromId), target = observe(toId);
    boolean complete =
        source.holding() != null
            && target.holding() != null
            && !source.holding().holds()
            && target.holding().holds();
    boolean original =
        source.holding() != null
            && target.holding() != null
            && source.holding().holds()
            && !target.holding().holds();
    if (complete) return;
    if (failure != null && !(failure instanceof OutcomeUnknownException) && original)
      // The add refused while a third object holds the name: a name in use, by the shared rule.
      throw toId.equals(failure.objectId().orElse(null))
          ? kms.keys().duplicateName(failure, List.of(name), toId, fromId)
          : failure;
    String observed = "read back: " + source.describe(name) + "; " + target.describe(name);
    String what =
        failure == null
            ? "both items succeeded but the transfer is not verified"
            : failure instanceof OutcomeUnknownException
                ? "the batch's outcome is unknown (" + failure.getMessage() + ")"
                : "the server refused the batch ("
                    + failure.getClass().getSimpleName()
                    + ") but its original"
                    + " state is not verified";
    OutcomeUnknownException unknown =
        new OutcomeUnknownException(
            OP
                + " "
                + name
                + " from "
                + fromId
                + " to "
                + toId
                + ": "
                + what
                + "; "
                + observed
                + "; read both objects before deciding what to do, rather than repeating the move blindly",
            failure,
            OP,
            fromId,
            failure == null ? null : failure.result().orElse(null),
            failure == null ? null : failure.response().orElse(null));
    for (Observed o : List.of(source, target))
      if (o.failure() != null) unknown.addSuppressed(o.failure());
    throw unknown;
  }

  /**
   * The Delete Attribute of exactly this Name value: by value (Current Attribute) from KMIP 2.0;
   * on 1.x by the Attribute Index the read reported for it (stable when other instances are
   * deleted, KMIP 1.4 section 2.1.1). Never a delete without a selector, which would remove every
   * Name (2.x) or the instance at index 0 (1.x).
   */
  private Request delete(Holding from) {
    if (!kms.protocolVersion().legacyAttributes())
      return Requests.deleteAttribute()
          .uniqueIdentifier(fromId)
          .attribute(Attributes.name(name))
          .build();
    return Requests.deleteAttribute()
        .uniqueIdentifier(fromId)
        .add(text(ATTRIBUTE_NAME, "Name"))
        .add(integer(ATTRIBUTE_INDEX, from.legacyIndex()))
        .build();
  }

  /**
   * Classifies the correlated reply: both items Success in request order is applied; the delete
   * Failed with nothing after it, or the delete Operation Undone followed by the add Failed, is an
   * acknowledged refusal of the failed item, typed by its own result. Anything else (Pending, a
   * Success left beside a failure, whose undo is not confirmed, another shape) is an unknown outcome.
   */
  private Reply reply(Response response) throws ProtocolException {
    if (response.messageLevelFailure())
      return new Reply(
          false,
          Failures.fromResult(
              new Failures.Call(OP, false, fromId, false),
              OP + " " + fromId,
              response.results().get(0),
              null));
    List<Integer> order = response.requestIndexes();
    if (response.requestCount() != 2
        || order.isEmpty()
        || order.size() > 2
        || order.get(0) != 0
        || (order.size() == 2 && order.get(1) != 1))
      throw new ProtocolException(
          "Batch reply items " + order + " do not answer the delete and the add in order",
          response.message(),
          null);
    Result delete = response.results().get(0);
    Result add = order.size() == 2 ? response.results().get(1) : null;
    if (add != null && delete.successful() && add.successful()) return new Reply(true, null);
    if (add == null && delete.status() == Enums.ResultStatus.OPERATION_FAILED.code())
      return new Reply(false, refusal(fromId, "taking the name off", delete));
    if (add != null
        && delete.status() == Enums.ResultStatus.OPERATION_UNDONE.code()
        && add.status() == Enums.ResultStatus.OPERATION_FAILED.code())
      return new Reply(false, refusal(toId, "giving the name to", add));
    throw new ProtocolException(
        "Ordered Undo batch replied "
            + status(delete)
            + " then "
            + (add == null ? "nothing" : status(add))
            + "; whether the name moved is not confirmed",
        response.message(),
        null);
  }

  private KmsException refusal(String id, String step, Result result) {
    return Failures.fromResult(
        new Failures.Call(OP, false, id, false),
        OP + " " + name + ": " + step + " " + id,
        result,
        null);
  }

  private static String status(Result r) {
    return r.statusEnum().map(Enum::name).orElse("status " + r.status());
  }

  /** One Get Attributes of the Name of {@code id}; pre-send failures stay typed and definite. */
  private Holding holding(String id) {
    boolean legacy = kms.protocolVersion().legacyAttributes();
    Request request =
        Requests.getAttributes().uniqueIdentifier(id).add(text(ATTRIBUTE_NAME, "Name")).build();
    return kms.execute(
        "attributes",
        Kms.Kind.READ,
        id,
        s -> {
          Result result = s.call(request);
          try {
            Ttlv payload = result.requirePayload();
            if (!legacy) {
              int count = 0;
              for (String n : AttributeReader.read(payload).names()) if (n.equals(name)) count++;
              return new Holding(id, count, -1);
            }
            // KMIP 1.x: an omitted Attribute Index means 0; two instances with one index (two that
            // omit it, say) cannot be told apart, so neither can be deleted exactly.
            Set<Integer> indexes = new HashSet<>();
            List<Integer> matching = new ArrayList<>();
            for (Ttlv a : payload.children(ATTRIBUTE)) {
              if (!a.require(ATTRIBUTE_NAME).textValue().equals("Name")) continue;
              int index = a.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0);
              if (index < 0)
                throw new ProtocolException(
                    "Get Attributes reports a negative Name Attribute Index",
                    result.batchItem(),
                    null);
              if (!indexes.add(index))
                throw new UnsupportedException(
                    OP
                        + " "
                        + id
                        + ": the server reports two Name instances with Attribute Index "
                        + index
                        + ", so KMIP "
                        + kms.protocolVersion()
                        + " cannot select exactly one to delete;"
                        + " nothing was changed",
                    null,
                    OP,
                    id,
                    null,
                    null);
              if (a.require(ATTRIBUTE_VALUE).require(NAME_VALUE).textValue().equals(name))
                matching.add(index);
            }
            return new Holding(id, matching.size(), matching.isEmpty() ? -1 : matching.get(0));
          } catch (IllegalArgumentException | IllegalStateException e) {
            throw new ProtocolException(
                "Malformed Get Attributes response", result.batchItem(), null);
          }
        });
  }

  /**
   * A read-back of {@code id}; its failure is an observation, not thrown. A closed {@code Kms}
   * (closed by another thread after the batch) is one too; any other unchecked failure is not.
   */
  private Observed observe(String id) {
    if (kms.closed()) return new Observed(id, null, new IllegalStateException("Kms is closed"));
    if (kms.remainingNanos() <= 0)
      return new Observed(
          id,
          null,
          new TransientException(
              OP + " " + id + ": no time left in the call's deadline to read it back",
              null,
              OP,
              id,
              null,
              null));
    try {
      return new Observed(id, holding(id), null);
    } catch (KmsException e) {
      return new Observed(id, null, e);
    } catch (IllegalStateException e) {
      if (!kms.closed()) throw e;
      return new Observed(id, null, e);
    }
  }
}
