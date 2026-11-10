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
package dev.keytend.kmip.micrometer;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.BiConsumer;

/**
 * The gauges and function counters of one SDK object, read each time a registry publishes. Get one
 * from {@link KmipMeters#connections}, {@link KmipMeters#localKeys} or {@link
 * KmipMeters#tlsIdentity}.
 *
 * <ul>
 *   <li>{@link #bindTo} registers the meters in a registry. A binder may be bound to several.
 *   <li>{@link #close()} removes them from each registry. It never closes a registry.
 *   <li>Close the binder when you close its object. Meters left in a registry after that read NaN
 *       once the object is gone.
 * </ul>
 *
 * <p>Thread-safe.
 *
 * @since 0.10.0
 */
public final class KmipMeterBinder implements MeterBinder, AutoCloseable {
  /**
   * One lock per registry, shared by every binder of this module: a bind or a close is one
   * transaction on the registry, so two binders never both see a meter as new (Micrometer hands the
   * second the first's meter) and each removes only meters it registered.
   */
  private static final Map<MeterRegistry, Object> REGISTRY_LOCKS =
      Collections.synchronizedMap(new WeakHashMap<>());

  /** Registers the meters in a registry; null once closed, so the object is no longer held. */
  private BiConsumer<MeterRegistry, List<Meter>> register;

  /** The meters registered, by registry (identity). */
  private final IdentityHashMap<MeterRegistry, List<Meter>> bound = new IdentityHashMap<>();

  private boolean closed;

  /** {@code register} registers the meters in a registry, adding each to the list. */
  KmipMeterBinder(BiConsumer<MeterRegistry, List<Meter>> register) {
    this.register = register;
  }

  private static Object lock(MeterRegistry registry) {
    return REGISTRY_LOCKS.computeIfAbsent(registry, r -> new Object());
  }

  /**
   * Registers the meters in {@code registry}. Does nothing when they are registered there already.
   *
   * <p>Each meter must be new to the registry, and distinct after the registry's filters. The bind
   * is refused when:
   *
   * <ul>
   *   <li>the registry has a meter of the same name and tags already, from another binder of
   *       another object or of the same one. Micrometer would hand it back, reading the other
   *       binder's object, and either binder's {@link #close()} would remove it from under the
   *       other;
   *   <li>a {@link io.micrometer.core.instrument.config.MeterFilter} maps two of this binder's
   *       meters to one, such as a filter that drops the {@code endpoint} tag. The meter would read
   *       only the first;
   *   <li>the registry refuses a meter, such as one of another type under the same name.
   * </ul>
   *
   * <p>Then this binder removes the meters it registered, keeps none, and throws. Meters that were
   * in the registry before are left alone. To bind two sources, give each binder tags of its own
   * ({@link KmipMeters#connections(dev.keytend.kmip.kms.Kms, Iterable)} and the like).
   *
   * <p>Binds and closes of this module's binders on one registry run one at a time. A meter the
   * application registers at the same moment is not covered.
   *
   * @param registry the registry, which stays the caller's
   * @throws IllegalStateException when this binder is closed, or a meter is in the registry
   *     already, or two of its meters are one after the registry's filters
   * @throws RuntimeException what the registry throws when it refuses a meter
   */
  @Override
  public synchronized void bindTo(MeterRegistry registry) {
    Objects.requireNonNull(registry, "registry");
    if (closed) throw new IllegalStateException("This KmipMeterBinder is closed");
    if (bound.containsKey(registry)) return;
    synchronized (lock(registry)) {
      Set<Meter> before = identitySet();
      before.addAll(registry.getMeters());
      List<Meter> meters = new ArrayList<>();
      try {
        register.accept(registry, meters);
      } catch (RuntimeException | Error refused) {
        removeNew(registry, meters, before);
        throw refused;
      }
      Set<Meter> distinct = identitySet();
      for (Meter m : meters) {
        boolean existed = before.contains(m);
        if (existed || !distinct.add(m)) {
          removeNew(registry, meters, before);
          throw new IllegalStateException(
              "The registry has a meter "
                  + m.getId().getName()
                  + " "
                  + m.getId().getTags()
                  + (existed
                      ? " already, of another source: give this binder tags of its own"
                      : " twice from this binder, its filters having made two meters one:"
                          + " keep the tags that tell them apart"));
        }
      }
      bound.put(registry, meters);
    }
  }

  /** Removes from {@code registry} the meters of {@code meters} that were not in {@code before}. */
  private static void removeNew(MeterRegistry registry, List<Meter> meters, Set<Meter> before) {
    List<Meter> made = new ArrayList<>(meters);
    made.removeIf(before::contains);
    removeHeld(registry, made);
  }

  /**
   * Removes from {@code registry} each of {@code meters} it still holds, the very object. Micrometer
   * removes by name and tags, so a meter the registry removed (a {@code clear()}, say) and another
   * source then registered under the same name and tags is that source's, and stays.
   */
  private static void removeHeld(MeterRegistry registry, List<Meter> meters) {
    Set<Meter> held = identitySet();
    held.addAll(registry.getMeters());
    for (Meter m : meters) if (held.remove(m)) registry.remove(m);
  }

  private static Set<Meter> identitySet() {
    return Collections.newSetFromMap(new IdentityHashMap<>());
  }

  /**
   * The meters registered in {@code registry}.
   *
   * @param registry a registry
   * @return the meters this binder registered there; empty when none
   */
  public synchronized List<Meter> meters(MeterRegistry registry) {
    List<Meter> meters = bound.get(registry);
    return meters == null ? List.of() : List.copyOf(meters);
  }

  /**
   * Removes the meters from every registry they were registered in, those the registry still holds:
   * a meter of the same name and tags registered after the registry removed this binder's (another
   * binder's, after a {@code clear()}) stays. Closes and binds of this module's binders on one
   * registry run one at a time; a meter the application registers in place of one of these at the
   * same moment is not covered. Idempotent.
   */
  @Override
  public synchronized void close() {
    closed = true;
    register = null;
    for (Map.Entry<MeterRegistry, List<Meter>> e : bound.entrySet())
      synchronized (lock(e.getKey())) {
        removeHeld(e.getKey(), e.getValue());
      }
    bound.clear();
  }
}
