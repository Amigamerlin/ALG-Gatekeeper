using ALGGatekeeper.DTOs;
using ALGGatekeeper.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;

namespace ALGGatekeeper
{
    /// <summary>
    /// events of one log read in one cycle
    /// </summary>
    internal sealed class ScanResult
    {
        /// <summary>events that appeared since the previous cycle</summary>
        public List<ExtractedEventRecord> NewEvents { get; } = new List<ExtractedEventRecord>();

        /// <summary>events younger than the requested maximum age</summary>
        public List<ExtractedEventRecord> TimeFramedEvents { get; } = new List<ExtractedEventRecord>();
    }

    /// <summary>
    /// What the rules need from one log: how far back, and which events can be relevant at all.
    /// </summary>
    internal sealed class LogRequest
    {
        private readonly List<IReadOnlyList<string>> _boosterSets = new List<IReadOnlyList<string>>();
        private bool _acceptAll;

        /// <summary>the largest EventAge of the rules reading this log (0 if they all use OnlyNew)</summary>
        public int MaxAgeSeconds { get; set; }

        /// <summary>registers the boosters of one rule; a rule without boosters makes every event relevant</summary>
        public void AddBoosters(IReadOnlyList<string> boosters)
        {
            if (boosters == null || boosters.Count == 0)
                _acceptAll = true;
            else
                _boosterSets.Add(boosters);
        }

        /// <summary>identifies the filter; when it changes, cached decisions are invalid</summary>
        public string FilterKey => _acceptAll ? "*" : string.Join("|", _boosterSets.Select(b => string.Join("\u0001", b)).OrderBy(k => k, StringComparer.Ordinal));

        /// <summary>true if at least one rule could use this event (all boosters of that rule are contained)</summary>
        public bool IsRelevant(string xml)
        {
            if (_acceptAll)
                return true;

            foreach (IReadOnlyList<string> set in _boosterSets)
            {
                bool all = true;
                for (int i = 0; i < set.Count; i++)
                {
                    if (xml.IndexOf(set[i], StringComparison.Ordinal) < 0)
                    {
                        all = false;
                        break;
                    }
                }

                if (all)
                    return true;
            }

            return false;
        }
    }

    /// <summary>
    /// Reads the Windows event logs. Remembers per log what was already seen.
    /// Memory: only events that at least one rule can use (all boosters of a rule contained) keep their XML;
    /// of all other events only the record id is remembered, so they are not rendered again in the next cycle
    /// (rendering is the most expensive part). Nothing older than the time frame is kept.
    /// </summary>
    internal sealed class EventScanner
    {
        private readonly ILogger _logger;
        private readonly DateTime _start;
        private readonly int _maxEvents;
        private readonly TimeSpan _missingLogRetry;

        private readonly Dictionary<string, DateTime> _lastEvent = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        /// <summary>per log: record id -> event (null = not relevant for any rule)</summary>
        private readonly Dictionary<string, Dictionary<long, ExtractedEventRecord>> _xmlCache = new Dictionary<string, Dictionary<long, ExtractedEventRecord>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _cacheFilterKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, DateTime> _missingLogs = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _limitWarned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public EventScanner(ILogger logger, DateTime start, int maxEventsPerLog, TimeSpan missingLogRetry)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _start = start;
            _maxEvents = maxEventsPerLog;
            _missingLogRetry = missingLogRetry;
        }

        /// <summary>
        /// reads one log; returns null if the log does not exist or can not be read
        /// </summary>
        public ScanResult Scan(string logName, LogRequest request, DateTime reference)
        {
            int maxAgeSeconds = request.MaxAgeSeconds;
            if (_missingLogs.TryGetValue(logName, out DateTime retryAt))
            {
                if (DateTime.UtcNow < retryAt)
                    return null;
                _missingLogs.Remove(logName);
            }

            if (!_lastEvent.TryGetValue(logName, out DateTime previousLast))
                previousLast = _start; // events before the service started are not "new"

            DateTime newest = previousLast;
            DateTime frameStart = reference.AddSeconds(-Math.Max(0, maxAgeSeconds));

            string filterKey = request.FilterKey;
            _xmlCache.TryGetValue(logName, out Dictionary<long, ExtractedEventRecord> oldCache);
            if (oldCache != null && (!_cacheFilterKey.TryGetValue(logName, out string oldKey) || oldKey != filterKey))
                oldCache = null; // the rules changed, earlier relevance decisions are not valid anymore
            var newCache = new Dictionary<long, ExtractedEventRecord>();
            var result = new ScanResult();
            int read = 0;

            _logger.Dump($"Scanning {logName}", SeverityLevel.Debug);

            try
            {
                var query = new EventLogQuery(logName, PathType.LogName) { ReverseDirection = true };

                using (var reader = new EventLogReader(query))
                {
                    while (true)
                    {
                        if (read++ >= _maxEvents)
                        {
                            // every record read counts, relevant or not: this bounds both the time and the memory of a cycle
                            if (_limitWarned.Add(logName))
                                _logger.Dump($"{logName}: more than {_maxEvents} events in one cycle, the oldest ones were skipped to protect CPU and memory. This usually means a massive attack or a much too long EventAge.", SeverityLevel.Warning);
                            break;
                        }

                        EventRecord record = reader.ReadEvent();
                        if (record == null)
                            break;

                        using (record)
                        {
                            // UTC everywhere: local time jumps at daylight saving changes and would distort the time frames
                            DateTime? created = record.TimeCreated?.ToUniversalTime();
                            if (!created.HasValue)
                                continue;

                            bool isNew = created.Value > previousLast;
                            bool inFrame = maxAgeSeconds > 0 && created.Value > frameStart;

                            // the log is read newest first: once an event is neither new nor in the frame, all older ones aren't either
                            if (!isNew && !inFrame)
                                break;

                            if (isNew && created.Value > newest)
                                newest = created.Value;

                            long? id = record.RecordId;
                            ExtractedEventRecord eer = null;
                            bool known = id.HasValue && oldCache != null && oldCache.TryGetValue(id.Value, out eer);

                            if (!known)
                            {
                                string xml = TryRenderXml(record);
                                if (xml != null && request.IsRelevant(xml))
                                    eer = new ExtractedEventRecord { TimeCreated = created.Value, Xml = xml, RecordId = id };
                            }

                            // remember the decision (an irrelevant event costs only its id)
                            if (inFrame && id.HasValue)
                                newCache[id.Value] = eer;

                            if (eer == null)
                                continue;

                            if (isNew)
                                result.NewEvents.Add(eer);

                            if (inFrame)
                                result.TimeFramedEvents.Add(eer);
                        }

                    }
                }
            }
            catch (EventLogNotFoundException)
            {
                _missingLogs[logName] = DateTime.UtcNow.Add(_missingLogRetry);
                _xmlCache.Remove(logName);
                _logger.Dump($"Event Log {logName} was not found, rules that use it will not work until it exists (checked again every {_missingLogRetry.TotalMinutes:0} minutes).", SeverityLevel.Info);
                return null;
            }
            catch (UnauthorizedAccessException ex)
            {
                _missingLogs[logName] = DateTime.UtcNow.Add(_missingLogRetry);
                _logger.Dump($"Event Log {logName} can not be read (access denied): {ex.Message}", SeverityLevel.Error);
                return null;
            }
            catch (EventLogException ex)
            {
                // keep what was read so far, try again next cycle
                _logger.Dump($"Error while reading {logName}: {ex.Message}", SeverityLevel.Warning);
            }

            _lastEvent[logName] = newest;
            // only events still inside the frame are kept: the cache can never grow beyond one time frame
            _xmlCache[logName] = newCache;
            _cacheFilterKey[logName] = filterKey;

            return result;
        }

        private string TryRenderXml(EventRecord record)
        {
            try
            {
                return record.ToXml();
            }
            catch (EventLogException ex)
            {
                _logger.Dump($"An event could not be rendered and was skipped: {ex.Message}", SeverityLevel.Debug);
                return null;
            }
        }
    }
}
