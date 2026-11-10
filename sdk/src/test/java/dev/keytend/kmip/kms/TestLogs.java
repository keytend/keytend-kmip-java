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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import org.slf4j.ILoggerFactory;
import org.slf4j.IMarkerFactory;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.event.Level;
import org.slf4j.helpers.AbstractLogger;
import org.slf4j.helpers.BasicMarkerFactory;
import org.slf4j.helpers.MessageFormatter;
import org.slf4j.helpers.NOPMDCAdapter;
import org.slf4j.spi.MDCAdapter;
import org.slf4j.spi.SLF4JServiceProvider;

/**
 * The SLF4J provider of the SDK's tests (sdk/pom.xml names it in {@code slf4j.provider}): it keeps
 * every event the SDK logs, at every level, so a test can assert on what was logged and, as
 * important, on what never is (key material, passwords). Open a {@link Capture} to see the events
 * logged while it is open. It is public in an exported package only so that SLF4J can instantiate
 * it; the SLF4J types it shows are not the SDK's API.
 */
@SuppressWarnings("exports")
public final class TestLogs implements SLF4JServiceProvider {
  /** One logged event, its message formatted. */
  public record Event(String logger, Level level, String message, Throwable thrown) {
    @Override
    public String toString() {
      return level + " " + logger + ": " + message + (thrown == null ? "" : " (" + thrown + ")");
    }
  }

  private static final List<Capture> CAPTURES = new CopyOnWriteArrayList<>();

  /** The events logged while open, from any thread. */
  public static final class Capture implements AutoCloseable {
    private final List<Event> events = new CopyOnWriteArrayList<>();

    private Capture() {
      CAPTURES.add(this);
    }

    /** Every event so far, in order. */
    public List<Event> events() {
      return List.copyOf(events);
    }

    /** The events so far that {@code which} accepts. */
    public List<Event> events(Predicate<Event> which) {
      List<Event> out = new ArrayList<>();
      for (Event e : events) if (which.test(e)) out.add(e);
      return out;
    }

    /** The messages of the events so far at {@code level} or more severe, of {@code logger}. */
    public List<String> messages(String logger, Level level) {
      List<String> out = new ArrayList<>();
      for (Event e : events)
        if (e.logger().equals(logger) && e.level().toInt() >= level.toInt()) out.add(e.message());
      return out;
    }

    @Override
    public void close() {
      CAPTURES.remove(this);
    }
  }

  /** Starts capturing. */
  public static Capture capture() {
    return new Capture();
  }

  private final ConcurrentMap<String, Logger> loggers = new ConcurrentHashMap<>();
  private final ILoggerFactory factory = name -> loggers.computeIfAbsent(name, Recording::new);
  private final IMarkerFactory markers = new BasicMarkerFactory();
  private final MDCAdapter mdc = new NOPMDCAdapter();

  /** The provider SLF4J instantiates. */
  public TestLogs() {}

  @Override
  public ILoggerFactory getLoggerFactory() {
    return factory;
  }

  @Override
  public IMarkerFactory getMarkerFactory() {
    return markers;
  }

  @Override
  public MDCAdapter getMDCAdapter() {
    return mdc;
  }

  @Override
  public String getRequestedApiVersion() {
    return "2.0.99";
  }

  @Override
  public void initialize() {}

  /** A logger enabled at every level that hands each event to the open captures. */
  private static final class Recording extends AbstractLogger {
    private static final long serialVersionUID = 1L;

    Recording(String name) {
      this.name = name;
    }

    @Override
    protected String getFullyQualifiedCallerName() {
      return null;
    }

    @Override
    protected void handleNormalizedLoggingCall(
        Level level, Marker marker, String format, Object[] args, Throwable thrown) {
      String message = MessageFormatter.basicArrayFormat(format, args);
      Event event = new Event(name, level, message, thrown);
      for (Capture c : CAPTURES) c.events.add(event);
    }

    @Override
    public boolean isTraceEnabled() {
      return true;
    }

    @Override
    public boolean isTraceEnabled(Marker marker) {
      return true;
    }

    @Override
    public boolean isDebugEnabled() {
      return true;
    }

    @Override
    public boolean isDebugEnabled(Marker marker) {
      return true;
    }

    @Override
    public boolean isInfoEnabled() {
      return true;
    }

    @Override
    public boolean isInfoEnabled(Marker marker) {
      return true;
    }

    @Override
    public boolean isWarnEnabled() {
      return true;
    }

    @Override
    public boolean isWarnEnabled(Marker marker) {
      return true;
    }

    @Override
    public boolean isErrorEnabled() {
      return true;
    }

    @Override
    public boolean isErrorEnabled(Marker marker) {
      return true;
    }
  }
}
