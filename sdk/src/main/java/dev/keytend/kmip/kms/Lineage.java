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

import java.time.Instant;
import java.util.*;
import java.util.function.Predicate;

/**
 * Rotation lineages: keys joined by Replacement Object and Replaced Object links. A step between two
 * keys counts only when both name each other, the newer key's Replaced Object link and the older
 * key's Replacement Object link: Re-key sets both, while whoever controls one key can set only
 * that key's links. Any link of the kind may confirm a step, so a key replaced twice (two callers
 * rotating it, on a server that re-keys a key already replaced, which breaks KMIP's rule of one
 * replacement object per Managed Object) has two branches, and the lineage is a {@link Tree}: every key reachable by confirmed
 * steps either way, siblings included. Walks take at most {@link #LIMIT} steps (a chain that
 * continues beyond them is an {@link UnsupportedException}), follow at most {@link #FANOUT} links of
 * a kind per key, and read at most {@link #BUDGET} keys, so links an attacker sets on keys it
 * controls cannot make a walk expensive. A link whose key no longer exists, cannot
 * be read, or comes back in a reply that is not valid is a {@link Gap}: it proves nothing, so a
 * search that meets one and finds nothing reports that it cannot decide, never that the key is
 * outside the chain. A newest key {@link KeyHandle#reconcile()} joined into another names it
 * with its Replacement Object link only, since KMIP allows a key one Replaced Object link:
 * between two keys of one tree that link says the first is not a newest key ({@link
 * Tree#joinedInto}); it confirms no step, so it adds no key to a tree.
 */
final class Lineage {
  /** The start of a {@link Gap}'s reason when its key no longer exists. */
  static final String GONE = "it no longer exists";

  /** How many confirmed steps a walk takes at most. */
  static final int LIMIT = 64;

  /** Orders identifiers: shorter first (so numeric identifiers sort numerically), then by character. */
  static final Comparator<String> IDENTIFIERS =
      Comparator.comparingInt(String::length).thenComparing(Comparator.naturalOrder());

  /**
   * The order among keys that replaced the same key, and among lineages with one name: the earliest
   * created (Initial Date) first, then the lowest identifier. Both are fixed when the key is made,
   * so every caller that sees the same keys orders them the same way.
   */
  static final Comparator<KeyAttributes> EARLIEST =
      Comparator.comparing((KeyAttributes a) -> a.creationDate().orElse(Instant.MAX))
          .thenComparing(KeyAttributes::id, IDENTIFIERS);

  /**
   * How many links of one kind the key a stored record names may have for a walk from it to follow
   * them: whoever controls a key can add any number, each costing a Get Attributes, so a forged
   * record fails fast. Other keys of a walk are bounded by {@link #BUDGET} only: a key many
   * callers replaced at once has one link per caller, and from the caller's own key only keys the
   * caller's server and SDK linked are reached.
   */
  static final int FANOUT = 32;

  /** How many keys one walk reads at most, whatever the links (four times {@link #LIMIT}). */
  static final int BUDGET = 4 * LIMIT;

  /** Reads a key's attributes; empty when the key no longer exists. */
  interface Reader {
    Optional<KeyAttributes> read(String id);
  }

  private Lineage() {}

  /** Whether {@code newer} replaced {@code older}, confirmed by both keys' links. */
  static boolean replaced(KeyAttributes newer, KeyAttributes older) {
    return newer.links(LinkKind.REPLACED).contains(older.id())
        && older.links(LinkKind.REPLACEMENT).contains(newer.id());
  }

  /** The reads of one walk: at most {@link #BUDGET}, whatever the links. */
  private static final class Budget {
    private final String operation;
    private final String id;
    private int reads;

    Budget(String operation, String id) {
      this.operation = operation;
      this.id = id;
    }

    /** Counts one read; checked before reading, so no failure of the read itself is taken for it. */
    void spend() {
      if (++reads > BUDGET)
        throw new ProtocolViolationException(
            operation
                + ": following the replacement links of "
                + id
                + " needs more than "
                + BUDGET
                + " keys",
            null,
            operation,
            id,
            null,
            null);
    }
  }

  /**
   * A link a walk could not resolve: {@code from} names {@code id}, which no longer exists, cannot be
   * read with these credentials, or came back in a reply that is not valid ({@code why}). It proves
   * nothing: the chain may continue beyond it.
   */
  record Gap(String from, String id, String why) {
    @Override
    public String toString() {
      return id + " (named by " + from + "; " + why + ")";
    }
  }

  /**
   * Whether a failure to read one key leaves that key unresolved, rather than failing the walk: the
   * key cannot be read with these credentials, the reply for it is not valid, or the server refuses
   * that object (archived, in a state it will not report, a field it rejects). Failures that say
   * nothing about the object (transient, server, unknown outcome, a refusal of this client's
   * credentials: {@link Failures#credentialsRefused}) propagate.
   */
  static boolean unresolvable(KmsException e) {
    // Refused credentials are not a fact about the object: they fail the walk.
    if (Failures.credentialsRefused(e)) return false;
    return e instanceof PermissionDeniedException
        || e instanceof ProtocolViolationException
        || e instanceof StateConflictException
        || e instanceof InvalidRequestException;
  }

  /**
   * Reads {@code id} for a walk, within its {@code budget} (whose limit propagates): empty, with a
   * {@link Gap} added to {@code gaps}, when the key cannot be resolved ({@link #unresolvable}).
   * Other failures propagate.
   */
  private static Optional<KeyAttributes> read(
      Budget budget, Reader read, String from, String id, List<Gap> gaps) {
    budget.spend();
    String why;
    try {
      Optional<KeyAttributes> key = read.read(id);
      if (key.isPresent()) return key;
      why = GONE + ", for example destroyed and purged";
    } catch (KmsException e) {
      if (!unresolvable(e)) throw e;
      why =
          e instanceof PermissionDeniedException
              ? "it cannot be read with these credentials"
              : e instanceof ProtocolViolationException
                  ? "the server's reply for it is not valid"
                  : "the server refused to read it: " + e.getMessage();
    }
    gaps.add(new Gap(from, id, why));
    return Optional.empty();
  }

  /**
   * A lineage tree: the keys reachable from a start key through steps confirmed by both keys' links
   *, in either direction, so a key's predecessors, its successors, and the other replacements
   * of any of them (siblings: callers that replaced one key at once leave several branches). The
   * walk goes first forward from the start (its successors), then back (every confirmed
   * predecessor of each key), then from every key reached in both directions, and stops at the
   * first key {@code stop} accepts (the tree is then partial). Bounds: at most {@link #LIMIT} steps
   * forward from the start or from a key reached walking back, and {@link #LIMIT} generations back
   * from the start (beyond them: {@link #beyondForward()}, {@link #beyondBack()}); at most {@link
   * #FANOUT} links of a kind on the start when it is a stored record's key; at most {@link #BUDGET}
   * keys read ({@link #limit()}). Duplicate links count once.
   */
  static final class Tree {
    private final String operation;
    private final KeyAttributes start;
    private final boolean own;
    private final boolean pastDestroyed;
    private final Reader reader;
    private final Map<String, KeyAttributes> keys = new LinkedHashMap<>();
    private final Map<String, Integer> depth = new HashMap<>();
    private final Map<String, Set<String>> successors = new HashMap<>();
    private final Map<String, Set<String>> predecessors = new HashMap<>();
    private final Map<String, List<String>> unconfirmed = new HashMap<>();
    private Map<String, Set<String>> joins;

    /** Keys a link named that no longer exist (read, and the server said so). */
    private final Set<String> gone = new HashSet<>();

    private Map<String, Set<String>> joinedFrom;
    private final Map<String, Optional<KeyAttributes>> read = new HashMap<>();
    private final List<Gap> gapsForward = new ArrayList<>();
    private final List<Gap> gapsBack = new ArrayList<>();
    private final Set<String> expandedForward = new HashSet<>();
    private final Set<String> expandedBack = new HashSet<>();
    private final Set<String> reread = new HashSet<>();
    private RuntimeException limit;
    private boolean beyondForward;
    private boolean beyondBack;
    private KeyAttributes found;
    private int reads;

    private Tree(
        String operation, KeyAttributes start, boolean own, boolean pastDestroyed, Reader reader) {
      this.operation = operation;
      this.start = start;
      this.own = own;
      this.pastDestroyed = pastDestroyed;
      this.reader = reader;
      keys.put(start.id(), start);
      depth.put(start.id(), 0);
    }

    /** The key the walk stopped at ({@code stop} accepted it), if any. */
    Optional<KeyAttributes> found() {
      return Optional.ofNullable(found);
    }

    /** The keys of the tree as far as walked, the start first. */
    Collection<KeyAttributes> keys() {
      return Collections.unmodifiableCollection(keys.values());
    }

    KeyAttributes start() {
      return start;
    }

    /** The confirmed replacements of {@code id} in the tree. */
    Set<String> successors(String id) {
      return successors.getOrDefault(id, Set.of());
    }

    /** The confirmed predecessors of {@code id} in the tree. */
    Set<String> predecessors(String id) {
      return predecessors.getOrDefault(id, Set.of());
    }

    /**
     * The keys of the tree {@code id} was joined into: {@code id} has no confirmed replacement, and
     * its Replacement Object link names them, while they do not name it back ({@link
     * KeyHandle#reconcile()} joins a newest key so: the key it joins into has a Replaced
     * Object link already, and KMIP allows one). Only keys the walk reached by confirmed steps count,
     * so a join adds no key to the tree; it only says that {@code id} is not a newest key.
     */
    Set<String> joinedInto(String id) {
      return joins().getOrDefault(id, Set.of());
    }

    /** The keys of the tree joined into {@code id} ({@link #joinedInto}). */
    Set<String> joinedFrom(String id) {
      joins();
      return joinedFrom.getOrDefault(id, Set.of());
    }

    /** The keys {@code id} leads to: its confirmed replacements and the keys it was joined into. */
    Set<String> newer(String id) {
      Set<String> out = new LinkedHashSet<>(successors(id));
      out.addAll(joinedInto(id));
      return out;
    }

    /** The joins among the keys walked, computed once. */
    private Map<String, Set<String>> joins() {
      if (joins != null) return joins;
      joins = new HashMap<>();
      joinedFrom = new HashMap<>();
      unconfirmed.forEach(
          (from, named) -> {
            if (!successors(from).isEmpty()) return;
            for (String to : named)
              if (!to.equals(from) && keys.containsKey(to)) {
                joins.computeIfAbsent(from, x -> new LinkedHashSet<>()).add(to);
                joinedFrom.computeIfAbsent(to, x -> new LinkedHashSet<>()).add(from);
              }
          });
      return joins;
    }

    /** Links met that could not be resolved, walking forward (Replacement Object links). */
    List<Gap> gapsForward() {
      return List.copyOf(gapsForward);
    }

    /** Links met that could not be resolved, walking back (Replaced Object links). */
    List<Gap> gapsBack() {
      return List.copyOf(gapsBack);
    }

    /** The first of the walk's own limits it met (too many links on a key, too many reads), or null. */
    RuntimeException limit() {
      return limit;
    }

    /** How many keys the walk read (at most {@link #BUDGET}, and one more when it met that limit). */
    int reads() {
      return reads;
    }

    /** Whether a confirmed successor lay more than {@link #LIMIT} steps forward. */
    boolean beyondForward() {
      return beyondForward;
    }

    /** Whether a confirmed predecessor of the start lay more than {@link #LIMIT} generations back. */
    boolean beyondBack() {
      return beyondBack;
    }

    /**
     * Whether {@code ancestor} reaches {@code id} by confirmed steps forward and joins ({@link
     * #newer}), within the tree.
     */
    boolean descends(String id, String ancestor) {
      Deque<String> queue = new ArrayDeque<>(List.of(ancestor));
      Set<String> seen = new HashSet<>(queue);
      while (!queue.isEmpty()) {
        String k = queue.poll();
        if (k.equals(id)) return true;
        for (String s : newer(k)) if (seen.add(s)) queue.add(s);
      }
      return false;
    }

    /**
     * The tips: keys of the tree without a confirmed replacement and not joined into another key of
     * the tree ({@link #joinedInto}). A key whose replacements cannot be resolved and none of which
     * is confirmed may not be a tip, so the tips are unknown: {@link StateConflictException}; one
     * that names existing replacements none of which names it back, and none of which is in the
     * tree, is a {@link ProtocolViolationException} (as for a chain). Unresolved links walking
     * back are passed over: retirement destroys a tree's oldest keys only when it has one tip ({@link
     * KeyHandle#retirePredecessors}), so nothing lives beyond them.
     *
     * @throws UnsupportedException when a successor lay more than {@link #LIMIT} steps on
     * @throws ProtocolViolationException for the walk's own limits, as for {@link #limit()}
     */
    List<KeyAttributes> tips() {
      if (limit != null) throw limit;
      if (beyondForward)
        throw new UnsupportedException(
            operation
                + ": "
                + start.id()
                + "'s lineage continues more than "
                + LIMIT
                + " rotations on;"
                + " continue from a newer key's handle, or find the current key by name",
            null,
            operation,
            start.id(),
            null,
            null);
      List<KeyAttributes> tips = new ArrayList<>();
      RuntimeException retiredEnd = null;
      for (KeyAttributes k : keys.values()) {
        if (!successors(k.id()).isEmpty()) continue;
        List<Gap> gaps = gapsForward.stream().filter(g -> g.from().equals(k.id())).toList();
        // A key no longer in use whose replacements are all gone: a branch being retired from its
        // newest end. Not a newest key while another remains.
        if ((!gaps.isEmpty() || !unconfirmed.getOrDefault(k.id(), List.of()).isEmpty())
            && retiredEnd(k)) {
          if (retiredEnd == null)
            retiredEnd =
                new StateConflictException(
                        operation
                            + ": the rotation lineage of "
                            + start.id()
                            + " ends at "
                            + k.id()
                            + ", which is "
                            + k.state()
                            + " and whose replacements no longer exist, so it has no newest key in use;"
                            + " find the current key by name (findByName)",
                        null,
                        operation,
                        start.id(),
                        null,
                        null)
                    .because(StateConflictException.Conflict.LINEAGE);
          continue;
        }
        if (!gaps.isEmpty())
          throw new StateConflictException(
                  operation
                      + ": the rotation lineage of "
                      + start.id()
                      + " cannot be followed past "
                      + gaps
                      + ", so its newest key cannot be found; find the current key by name (findByName), or"
                      + " use a handle on the key you know is current. Purging a key in the middle of a chain"
                      + " breaks it: retire the oldest keys first (docs/kms-design.md, \"Retiring keys\")",
                  null,
                  operation,
                  start.id(),
                  null,
                  null)
              .because(StateConflictException.Conflict.LINEAGE);
        if (!joinedInto(k.id()).isEmpty()) continue;
        List<String> named = unconfirmed.getOrDefault(k.id(), List.of());
        if (!named.isEmpty())
          throw new ProtocolViolationException(
              operation
                  + ": "
                  + k.id()
                  + " names "
                  + named
                  + " as its replacement, but none names "
                  + k.id()
                  + " as the key it replaced",
              null,
              operation,
              start.id(),
              null,
              null);
        tips.add(k);
      }
      RuntimeException cycle = cycle();
      if (cycle != null) throw cycle;
      if (tips.isEmpty() && retiredEnd != null) throw retiredEnd;
      tips.sort(TIPS);
      return tips;
    }

    /**
     * Whether {@code k}, a key without a confirmed replacement, is the end of a branch being retired
     * from its newest end: it is no longer Active or Pre-Active (Deactivated, Compromised or
     * destroyed), and every replacement it names no longer exists, or exists destroyed (a server
     * may drop a destroyed key's links, so the link back is gone too). {@link
     * KeyHandle#retirePredecessors} destroys the keys of a joined branch newest first; one that
     * stopped part-way on a server that purges destroyed keys leaves such a key, and the newest
     * key that cannot be followed past it is one nobody can use any more.
     */
    private boolean retiredEnd(KeyAttributes k) {
      KeyState state = k.state();
      if (state == KeyState.ACTIVE || state == KeyState.PRE_ACTIVE || state == KeyState.UNKNOWN)
        return false;
      for (String id : k.links(LinkKind.REPLACEMENT).stream().distinct().toList()) {
        if (gone.contains(id)) continue;
        Optional<KeyAttributes> r = read.getOrDefault(id, Optional.empty());
        if (r.isEmpty()) return false;
        KeyState rs = r.get().state();
        if (rs != KeyState.DESTROYED && rs != KeyState.DESTROYED_COMPROMISED) return false;
      }
      return true;
    }

    /**
     * A {@link ProtocolViolationException} when the confirmed links and joins among the keys walked
     * form a cycle (keys that replaced each other, or a key joined into one it replaced), or null.
     */
    RuntimeException cycle() {
      Map<String, Integer> in = new HashMap<>();
      for (String k : keys.keySet()) in.put(k, 0);
      for (String k : keys.keySet())
        for (String s : newer(k)) if (in.containsKey(s)) in.merge(s, 1, Integer::sum);
      Deque<String> ready = new ArrayDeque<>();
      in.forEach(
          (k, n) -> {
            if (n == 0) ready.add(k);
          });
      int removed = 0;
      while (!ready.isEmpty()) {
        String k = ready.poll();
        removed++;
        for (String s : newer(k))
          if (in.containsKey(s) && in.merge(s, -1, Integer::sum) == 0) ready.add(s);
      }
      return removed == keys.size()
          ? null
          : Lineage.cycle(operation, start.id(), "Replacement Object");
    }

    /** The tip {@link KeyHandle#latest()} returns: the first in {@link #TIPS}. */
    KeyAttributes chosen() {
      return tips().get(0);
    }

    private Tree walk(Predicate<KeyAttributes> stop) {
      try {
        // Forward from the start: its successors, nearest first (free for a key never rotated).
        if (forwardFrom(List.of(start), stop)) return this;
        // Back from the start: every confirmed predecessor, generation by generation.
        List<KeyAttributes> level = List.of(start);
        for (int generation = 1; !level.isEmpty(); generation++) {
          List<KeyAttributes> older = new ArrayList<>();
          for (KeyAttributes k : level)
            for (KeyAttributes p : back(k)) {
              // A destroyed key just past the limit ends a walk that stops at one: it is taken in
              // (its predecessors are not read), and nothing lies beyond it.
              if (generation > LIMIT && (pastDestroyed || !destroyed(p))) {
                beyondBack = true;
                continue;
              }
              if (add(p, 0)) {
                if (stop.test(p)) {
                  found = p;
                  return this;
                }
                older.add(p);
              }
            }
          level = older;
        }
        // Then from every key reached, both ways: siblings, cousins, keys folded into others.
        for (boolean grew = true; grew; ) {
          grew = false;
          for (KeyAttributes k : new ArrayList<>(keys.values())) {
            if (!expandedForward.contains(k.id())) {
              grew = true;
              if (forwardFrom(List.of(k), stop)) return this;
            }
            if (!expandedBack.contains(k.id())) {
              grew = true;
              for (KeyAttributes p : back(k))
                if (add(p, 0) && stop.test(p)) {
                  found = p;
                  return this;
                }
            }
          }
        }
      } catch (ProtocolViolationException spent) {
        // more than BUDGET reads: nothing more can be read
        if (limit == null) limit = spent;
      }
      return this;
    }

    /** Walks forward from {@code from}, breadth first; true when {@code stop} accepted a key. */
    private boolean forwardFrom(List<KeyAttributes> from, Predicate<KeyAttributes> stop) {
      Deque<KeyAttributes> queue = new ArrayDeque<>(from);
      while (!queue.isEmpty()) {
        KeyAttributes k = queue.poll();
        if (!expandedForward.add(k.id())) continue;
        for (KeyAttributes s : forward(k)) {
          int d = depth.get(k.id()) + 1;
          if (d > LIMIT) {
            beyondForward = true;
            continue;
          }
          if (add(s, d)) {
            if (stop.test(s)) {
              found = s;
              return true;
            }
            queue.add(s);
          }
        }
      }
      return false;
    }

    /** Adds a key reached at {@code d} steps forward; false when it was in the tree already. */
    private boolean add(KeyAttributes k, int d) {
      if (keys.containsKey(k.id())) return false;
      keys.put(k.id(), k);
      depth.put(k.id(), d);
      return true;
    }

    /** {@code k}'s confirmed replacements, recording the edges, gaps and unconfirmed links. */
    private List<KeyAttributes> forward(KeyAttributes k) {
      expandedForward.add(k.id());
      List<KeyAttributes> out = new ArrayList<>();
      List<String> ids = links(k, LinkKind.REPLACEMENT);
      if (ids == null) return out;
      for (String id : ids) {
        Optional<KeyAttributes> newer = resolve(k.id(), id, gapsForward);
        if (newer.isEmpty()) continue;
        // Read before the link that confirms it was added (a reconcile or replacement linking
        // while this walk runs): read once more before taking it for unconfirmed.
        if (!replaced(newer.get(), k)) newer = reread(id, newer);
        if (!replaced(newer.get(), k)) {
          unconfirmed.computeIfAbsent(k.id(), x -> new ArrayList<>()).add(id);
          continue;
        }
        successors.computeIfAbsent(k.id(), x -> new LinkedHashSet<>()).add(id);
        predecessors.computeIfAbsent(id, x -> new LinkedHashSet<>()).add(k.id());
        out.add(keys.getOrDefault(id, newer.get()));
      }
      return out;
    }

    /**
     * {@code k}'s confirmed predecessors, recording the edges and gaps; none, and nothing read, for a
     * destroyed key when the walk stops at one ({@link #tree(String, KeyAttributes, boolean,
     * Predicate, Reader, boolean)}).
     */
    private List<KeyAttributes> back(KeyAttributes k) {
      expandedBack.add(k.id());
      List<KeyAttributes> out = new ArrayList<>();
      if (!pastDestroyed && destroyed(k)) return out;
      List<String> ids = links(k, LinkKind.REPLACED);
      if (ids == null) return out;
      for (String id : ids) {
        Optional<KeyAttributes> older = resolve(k.id(), id, gapsBack);
        if (older.isPresent() && !replaced(k, older.get())) older = reread(id, older);
        if (older.isEmpty() || !replaced(k, older.get())) continue;
        predecessors.computeIfAbsent(k.id(), x -> new LinkedHashSet<>()).add(id);
        successors.computeIfAbsent(id, x -> new LinkedHashSet<>()).add(k.id());
        out.add(keys.getOrDefault(id, older.get()));
      }
      return out;
    }

    /** {@code k}'s distinct links of {@code kind}; null (and a limit) when there are too many. */
    private List<String> links(KeyAttributes k, LinkKind kind) {
      List<String> ids = k.links(kind).stream().distinct().toList();
      // Only the start of a walk from a record's key is bounded: every other key is reached by a
      // step its own links confirm, and from the caller's own key only the caller's keys are
      // ; BUDGET bounds the reads either way.
      if (ids.size() > FANOUT && !own && k.id().equals(start.id())) {
        if (limit == null)
          limit =
              new ProtocolViolationException(
                  operation
                      + ": "
                      + k.id()
                      + " has "
                      + ids.size()
                      + " "
                      + kind
                      + " links, more than the "
                      + FANOUT
                      + " a rotation lineage follows",
                  null,
                  operation,
                  k.id(),
                  null,
                  null);
        return null;
      }
      return ids;
    }

    /**
     * {@code id} read again, once per walk, when it was read before: its attributes, also in the
     * tree, are replaced by the fresh ones. As read before when it cannot be read again.
     */
    private Optional<KeyAttributes> reread(String id, Optional<KeyAttributes> before) {
      if (!reread.add(id)) return before;
      if (++reads > BUDGET)
        throw new ProtocolViolationException(
            operation
                + ": following the replacement links of "
                + start.id()
                + " needs more than "
                + BUDGET
                + " keys",
            null,
            operation,
            start.id(),
            null,
            null);
      Optional<KeyAttributes> fresh;
      try {
        fresh = reader.read(id);
      } catch (KmsException e) {
        if (!unresolvable(e)) throw e;
        return before;
      }
      if (fresh.isEmpty()) return before;
      read.put(id, fresh);
      if (keys.containsKey(id)) keys.put(id, fresh.get());
      return fresh;
    }

    /** {@code id} as read once for this walk; empty (and a gap) when it cannot be resolved. */
    private Optional<KeyAttributes> resolve(String from, String id, List<Gap> gaps) {
      KeyAttributes known = keys.get(id);
      if (known != null) return Optional.of(known);
      Optional<KeyAttributes> cached = read.get(id);
      if (cached == null) {
        if (++reads > BUDGET)
          throw new ProtocolViolationException(
              operation
                  + ": following the replacement links of "
                  + start.id()
                  + " needs more than "
                  + BUDGET
                  + " keys",
              null,
              operation,
              start.id(),
              null,
              null);
        List<Gap> found = new ArrayList<>();
        cached = Lineage.read(new Budget(operation, start.id()), reader, from, id, found);
        read.put(id, cached);
        if (cached.isEmpty() && found.stream().anyMatch(g -> g.why().startsWith(GONE)))
          gone.add(id);
        if (!found.isEmpty()) gaps.addAll(found);
      } else if (cached.isEmpty()) gaps.add(new Gap(from, id, "it could not be resolved"));
      return cached;
    }
  }

  /**
   * The order among the tips of a tree ({@link KeyHandle#latest()}, and {@link
   * KmsKeys#findByName(String)} among keys with the name): an Active key first (one that can be used),
   * then one that holds a name (the one name lookups return), then {@link #EARLIEST}. Every caller that
   * sees the same keys chooses the same tip.
   */
  static final Comparator<KeyAttributes> TIPS =
      Comparator.comparing((KeyAttributes a) -> a.state() != KeyState.ACTIVE)
          .thenComparing(a -> a.names().isEmpty())
          .thenComparing(EARLIEST);

  /**
   * The lineage tree of {@code start}, walked until {@code stop} accepts a key (null: the whole
   * tree, within the bounds). {@code own}: the start is the caller's own key (a handle's), so its
   * links are all followed however many (a key many callers replaced at once); a key a stored record
   * names may be anyone's, and is bounded like every other key.
   */
  static Tree tree(
      String operation,
      KeyAttributes start,
      boolean own,
      Predicate<KeyAttributes> stop,
      Reader read) {
    return tree(operation, start, own, stop, read, true);
  }

  /**
   * {@link #tree(String, KeyAttributes, boolean, Predicate, Reader)}; with {@code pastDestroyed}
   * false, the walk does not go back past a destroyed key: its predecessors are not read, and a
   * destroyed key just past {@link #LIMIT} generations ends the walk there rather than counting as
   * {@link Tree#beyondBack()}.
   * For retirement and the listing ({@link KeyHandle#retirePredecessors}, {@link
   * KeyHandle#lineage()}): retirement destroys the oldest keys first, so the keys behind a destroyed
   * one were retired before it, and a server that keeps destroyed keys with their links (rather
   * than purging them) would otherwise make every lineage longer than {@link #LIMIT} rotations
   * unretirable however often it was retired. Forward from a destroyed key, the walk goes on as
   * ever (another newest key hanging off it is still found).
   */
  static Tree tree(
      String operation,
      KeyAttributes start,
      boolean own,
      Predicate<KeyAttributes> stop,
      Reader read,
      boolean pastDestroyed) {
    return new Tree(operation, start, own, pastDestroyed, read)
        .walk(stop == null ? k -> false : stop);
  }

  /** Whether {@code key} is destroyed (Destroyed or Destroyed Compromised). */
  static boolean destroyed(KeyAttributes key) {
    return key.state() == KeyState.DESTROYED || key.state() == KeyState.DESTROYED_COMPROMISED;
  }

  /**
   * Whether {@code key} provably lies beyond none of a walk's gaps: it exists and is not destroyed
   * (a server may drop a destroyed key's links), and lacks the link a key beyond such a gap must
   * have. A key older than a gap met walking back has a Replacement Object link (to its own
   * successor), one newer than a gap met walking forward a Replaced Object link; no step can be
   * confirmed without them. A search that did not find such a key is a proven mismatch. Beyond a
   * key purged in the middle of a tree, a sibling branch could lie too; {@link
   * KeyHandle#retirePredecessors} purges nothing while a tree has another newest key, so only a
   * purge by hand leaves one there.
   */
  static boolean beyondNone(KeyAttributes key, boolean gapsBack, boolean gapsForward) {
    KeyState state = key.state();
    return state != KeyState.DESTROYED
        && state != KeyState.DESTROYED_COMPROMISED
        && state != KeyState.UNKNOWN
        && (!gapsBack || key.links(LinkKind.REPLACEMENT).isEmpty())
        && (!gapsForward || key.links(LinkKind.REPLACED).isEmpty());
  }

  /**
   * The failure for a search that did not find its key while links of the tree could not be
   * resolved: {@code what} the search was for (completing "the ciphertext names ..."), and the
   * caller's advice.
   */
  static StateConflictException broken(
      String operation, String startId, String what, List<Gap> gaps, String advice) {
    return new StateConflictException(
            operation
                + ": "
                + what
                + " was not found in the rotation lineage of "
                + startId
                + ", which cannot"
                + " be followed past "
                + gaps.stream().map(Gap::toString).distinct().toList()
                + ", so it may be beyond them; "
                + advice,
            null,
            operation,
            startId,
            null,
            null)
        .because(StateConflictException.Conflict.LINEAGE);
  }

  /**
   * The confirmed replacements of {@code key} (each names it back), {@link #EARLIEST} first.
   * Replacements that cannot be resolved are passed over.
   */
  static List<KeyAttributes> replacements(String operation, KeyAttributes key, Reader read) {
    Budget budget = new Budget(operation, key.id());
    List<KeyAttributes> out = new ArrayList<>();
    List<Gap> gaps = new ArrayList<>();
    for (String id : key.links(LinkKind.REPLACEMENT).stream().distinct().toList())
      read(budget, read, key.id(), id, gaps).filter(r -> replaced(r, key)).ifPresent(out::add);
    out.sort(EARLIEST);
    return out;
  }

  /** The replacements of {@code key} that still exist. */
  static List<String> existingReplacements(String operation, KeyAttributes key, Reader read) {
    Budget budget = new Budget(operation, key.id());
    List<String> out = new ArrayList<>();
    for (String id : key.links(LinkKind.REPLACEMENT).stream().distinct().toList()) {
      budget.spend();
      if (read.read(id).isPresent()) out.add(id);
    }
    return out;
  }

  /**
   * A lineage walked back: its keys, oldest first and the start last; whether it continues past
   * {@link #LIMIT} steps, so that its first key was not reached; and the Replaced Object links of
   * the first key reached that were not followed (the object no longer exists, for example
   * destroyed and purged, the caller may not read it, or it does not name that key back). With
   * such links the lineage may start earlier than its first key: only a lineage with neither is
   * known to start there.
   */
  record Back(List<KeyAttributes> keys, boolean truncated, List<String> unresolved) {}

  /**
   * The keys of {@code start}'s lineage back to its first key, following the first confirmed
   * predecessor of each, at most {@link #LIMIT} steps. The walk's own limits (a cycle, a key with
   * more than {@link #FANOUT} links, more than {@link #BUDGET} reads) end it, as for a key that
   * replaced none: such a lineage starts no earlier than where the walk stopped. A key none of
   * whose Replaced Object links is confirmed ends it too, and {@link Back#unresolved()} names those
   * links: their targets no longer exist, cannot be read with these credentials, came back in a
   * reply that is not valid (a {@link ProtocolViolationException}), or do not name that key back.
   * Other failures of a read propagate.
   */
  static Back back(KeyAttributes start, Reader read) {
    Deque<KeyAttributes> walked = new ArrayDeque<>(List.of(start));
    Set<String> seen = new HashSet<>(Set.of(start.id()));
    KeyAttributes current = start;
    int reads = 0;
    for (int step = 1; ; step++) {
      List<String> ids = current.links(LinkKind.REPLACED);
      // The walk's limits, checked here rather than caught, so that no failure of a read can end
      // the walk as if the lineage started here.
      if (ids.size() > FANOUT) return new Back(new ArrayList<>(walked), false, List.of());
      List<String> unresolved = new ArrayList<>();
      Optional<KeyAttributes> older = Optional.empty();
      for (String id : ids) {
        if (++reads > BUDGET) return new Back(new ArrayList<>(walked), false, List.of());
        Optional<KeyAttributes> o;
        try {
          o = read.read(id);
        } catch (KmsException e) {
          if (!unresolvable(e)) throw e;
          o = Optional.empty();
        }
        // A link the walk does not follow, because its target cannot be read or does not confirm
        // it (a server that drops a destroyed key's links, or sets only one link at Re-key),
        // leaves the lineage's start open.
        if (o.isPresent() && replaced(current, o.get())) {
          older = o;
          break;
        }
        unresolved.add(id);
      }
      if (older.isEmpty()) return new Back(new ArrayList<>(walked), false, List.copyOf(unresolved));
      if (!seen.add(older.get().id())) return new Back(new ArrayList<>(walked), false, List.of());
      if (step > LIMIT) return new Back(new ArrayList<>(walked), true, List.of());
      current = older.get();
      walked.addFirst(current);
    }
  }

  private static ProtocolViolationException cycle(String operation, String id, String kind) {
    return new ProtocolViolationException(
        operation + ": the " + kind + " links of " + id + " form a cycle",
        null,
        operation,
        id,
        null,
        null);
  }
}
