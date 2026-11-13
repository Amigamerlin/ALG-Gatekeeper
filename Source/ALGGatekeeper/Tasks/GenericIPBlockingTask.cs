using ALGGatekeeper.Config;
using ALGGatekeeper.DTOs;
using ALGGatekeeper.Logging;
using ALGGatekeeper.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;

namespace ALGGatekeeper.Tasks
{
    internal class GenericIPBlockingTask : LogTask
    {
        #region static

        /// <summary>
        /// Maximum time a rule regex may spend on a single event.
        /// Event contents can be influenced by attackers (user names, URLs...), so a badly written
        /// regex must not be able to freeze the service (ReDoS).
        /// </summary>
        internal static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

        internal static GenericIPBlockingTask FromConfiguration(IPersistentTaskConfiguration configuration, ILogger logger)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration));

            if (string.IsNullOrWhiteSpace(configuration.Regex))
                throw new FormatException($"Task {configuration.TaskName}: the Regex is empty.");

            Regex regex;
            try
            {
                regex = new Regex(configuration.Regex, RegexOptions.Compiled | RegexOptions.CultureInvariant, RegexTimeout);
            }
            catch (ArgumentException ex)
            {
                throw new FormatException($"Task {configuration.TaskName}: the Regex is not valid ({ex.Message}).", ex);
            }

            GenericIPBlockingTask t = new GenericIPBlockingTask(logger)
            {
                Name = configuration.TaskName,
                Active = configuration.Active,
                Kind = configuration.Kind,
                Description = configuration.Description,
                LockTime = configuration.LockTime,
                OnlyNew = configuration.OnlyNewEvents,
                EventAge = configuration.EventAge,
                TriggerCount = configuration.TriggerCount,
                PermaBanCount = configuration.PermaBanCount,
                EventPath = (configuration.EventPath ?? string.Empty)
                    .Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(p => p.Trim())
                    .Where(p => p.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                Boosters = configuration.RegexBoosters.Where(b => !string.IsNullOrEmpty(b)).ToList(),
                Regex = regex
            };

            if (t.EventPath.Count == 0)
                throw new FormatException($"Task {configuration.TaskName}: no EventPath configured.");

            return t;
        }

        #endregion

        #region private members

        /// <summary>a strike (temporary ban) is forgotten after this time without a new one</summary>
        internal static readonly TimeSpan StrikeMemory = TimeSpan.FromDays(30);

        /// <summary>a trust is renewed at most this often (avoids rewriting state.xml every cycle)</summary>
        private static readonly TimeSpan TrustRenewalGranularity = TimeSpan.FromHours(1);

        private readonly object _syncObject = new object();

        /// <summary>ip -> UTC start of the temporary ban (Ban rules) or of the trust (Trust rules)</summary>
        private readonly Dictionary<IPAddress, DateTime> _blockedIPsToDate = new Dictionary<IPAddress, DateTime>();

        /// <summary>
        /// ip -> UTC time: events of this ip created at or before it are not counted again
        /// (they already caused a ban, or an administrator lifted the ban / revoked the trust)
        /// </summary>
        private readonly Dictionary<IPAddress, DateTime> _ignoreEventsUntil = new Dictionary<IPAddress, DateTime>();

        /// <summary>ip -> number of temporary bans and the UTC time of the last one</summary>
        private readonly Dictionary<IPAddress, StrikeInfo> _strikes = new Dictionary<IPAddress, StrikeInfo>();

        private readonly ILogger _logger;
        private DateTime _lastRegexTimeoutWarning = DateTime.MinValue;
        private long _stateVersion;

        #endregion

        #region internal .ctor

        internal GenericIPBlockingTask(ILogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        #endregion

        #region public properties

        /// <summary>seconds a temporary ban (or a trust) lasts</summary>
        public int LockTime { get; set; } = 3600;

        /// <summary>strings that must all be contained in an event before the (expensive) regex is applied</summary>
        public List<string> Boosters { get; set; } = new List<string>();

        /// <summary>after this many temporary bans the IP gets banned permanently, negative = never</summary>
        public int PermaBanCount { get; set; } = 3;

        /// <summary>this many matching events within EventAge cause a temporary ban</summary>
        public int TriggerCount { get; set; } = 5;

        public Regex Regex { get; set; } = null;

        /// <summary>Ban: found IPs get banned. Trust: found IPs are trusted (never banned) for LockTime seconds.</summary>
        public TaskKind Kind { get; set; } = TaskKind.Ban;

        public bool IsTrustTask => Kind == TaskKind.Trust;

        /// <summary>changes whenever bans, trusts or strikes change; used to save the state only when needed</summary>
        public long StateVersion => Interlocked.Read(ref _stateVersion);

        private void StateChanged() => Interlocked.Increment(ref _stateVersion);

        #endregion

        #region public operations

        /// <summary>
        /// the IPs currently banned (Ban rules) or trusted (Trust rules); expired entries are removed
        /// </summary>
        public List<IPAddress> GetTempBanVictims()
        {
            lock (_syncObject)
            {
                DateTime now = DateTime.UtcNow;
                bool changed = false;
                var current = new List<IPAddress>();

                foreach (IPAddress ip in _blockedIPsToDate.Keys.ToList())
                {
                    if (_blockedIPsToDate[ip].AddSeconds(LockTime) < now)
                    {
                        _blockedIPsToDate.Remove(ip);
                        changed = true;
                    }
                    else
                    {
                        current.Add(ip);
                    }
                }

                // events older than the time frame are never delivered again: their ignore marks can go
                DateTime oldestRelevant = now.AddSeconds(-EventAge).AddMinutes(-5);
                foreach (IPAddress ip in _ignoreEventsUntil.Where(p => p.Value < oldestRelevant).Select(p => p.Key).ToList())
                    _ignoreEventsUntil.Remove(ip);

                // strikes are forgotten after a long quiet time
                foreach (IPAddress ip in _strikes.Where(p => p.Value.LastUtc < now - StrikeMemory).Select(p => p.Key).ToList())
                {
                    _strikes.Remove(ip);
                    changed = true;
                }

                if (changed)
                    StateChanged();

                return current;
            }
        }

        /// <summary>
        /// the IPs that reached PermaBanCount strikes (Ban rules only); their strikes are reset
        /// </summary>
        public List<IPAddress> GetPermaBanVictims()
        {
            lock (_syncObject)
            {
                var permaList = new List<IPAddress>();
                if (PermaBanCount < 0 || Kind != TaskKind.Ban)
                    return permaList;

                foreach (var kvp in _strikes.Where(p => p.Value.Count >= PermaBanCount))
                {
                    permaList.Add(kvp.Key);
                    _logger.Dump($"{Name}: permanently banned {kvp.Key} (strike count {kvp.Value.Count} reached the limit of {PermaBanCount})", SeverityLevel.Info);
                }

                foreach (IPAddress ip in permaList)
                    _strikes.Remove(ip);

                if (permaList.Count > 0)
                    StateChanged();

                return permaList;
            }
        }

        protected override void OnComputeEvents(List<ExtractedEventRecord> events)
        {
            if (events == null || events.Count == 0)
                return;

            lock (_syncObject)
            {
                bool debug = _logger.IsEnabled(SeverityLevel.Debug);
                bool verbose = _logger.IsEnabled(SeverityLevel.Verbose);
                var sourceToCount = new Dictionary<IPAddress, int>();
                var newestEvent = new Dictionary<IPAddress, DateTime>();

                foreach (ExtractedEventRecord e in events)
                {
                    string xml = e?.Xml;
                    if (string.IsNullOrEmpty(xml))
                        continue;

                    if (debug)
                        _logger.Dump($"{Name}: Processing Event with timestamp {e.TimeCreated:o}", SeverityLevel.Debug);

                    bool abort = false;
                    foreach (string b in Boosters)
                    {
                        if (xml.IndexOf(b, StringComparison.Ordinal) < 0)
                        {
                            abort = true;
                            break;
                        }
                    }
                    if (abort)
                        continue;

                    if (debug)
                        _logger.Dump($"{Name}: boosters matched, checking XML {xml} against Regex {Regex}", SeverityLevel.Debug);

                    IPAddress ipAddress;
                    try
                    {
                        if (!IPAddressTools.TryExtract(Regex, xml, out ipAddress))
                            continue;
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        if (DateTime.UtcNow > _lastRegexTimeoutWarning.AddHours(1))
                        {
                            _logger.Dump($"{Name}: the regex took longer than {RegexTimeout.TotalSeconds}s on an event and was aborted. Please make the Regex of this task simpler (avoid leading .* and nested quantifiers).", SeverityLevel.Warning);
                            _lastRegexTimeoutWarning = DateTime.UtcNow;
                        }
                        continue;
                    }

                    if (_ignoreEventsUntil.TryGetValue(ipAddress, out DateTime ignoreUntil) && e.TimeCreated <= ignoreUntil)
                    {
                        if (verbose)
                            _logger.Dump($"{Name}: found {ipAddress} in an event that was already handled, not counted again", SeverityLevel.Verbose);
                        continue;
                    }

                    sourceToCount.TryGetValue(ipAddress, out int count);
                    sourceToCount[ipAddress] = count + 1;

                    if (!newestEvent.TryGetValue(ipAddress, out DateTime newest) || e.TimeCreated > newest)
                        newestEvent[ipAddress] = e.TimeCreated;

                    if (verbose)
                        _logger.Dump($"{Name}: found {ipAddress}, trigger count is {sourceToCount[ipAddress]}", SeverityLevel.Verbose);
                }

                DateTime now = DateTime.UtcNow;

                foreach (KeyValuePair<IPAddress, int> kvp in sourceToCount)
                {
                    if (kvp.Value < TriggerCount)
                        continue;

                    if (Kind == TaskKind.Trust)
                    {
                        // every successful login renews the trust period
                        // renewed at most hourly (fewer state writes), but always before half of the trust has passed
                        bool known = _blockedIPsToDate.TryGetValue(kvp.Key, out DateTime since);
                        TimeSpan renewAfter = TimeSpan.FromSeconds(Math.Min(TrustRenewalGranularity.TotalSeconds, LockTime / 2.0));
                        if (!known || now - since > renewAfter)
                        {
                            _blockedIPsToDate[kvp.Key] = now;
                            StateChanged();
                        }
                        if (!known)
                            _logger.Dump($"{Name}: {kvp.Key} logged in successfully and is trusted for {LockTime / 3600.0:0.#} hours (it will not be banned).", SeverityLevel.Info);
                        continue;
                    }

                    if (_blockedIPsToDate.ContainsKey(kvp.Key))
                        continue;

                    _blockedIPsToDate.Add(kvp.Key, now);

                    // the events that caused this ban must not cause another one later
                    _ignoreEventsUntil[kvp.Key] = newestEvent[kvp.Key];

                    _strikes.TryGetValue(kvp.Key, out StrikeInfo strikes);
                    _strikes[kvp.Key] = new StrikeInfo(strikes.Count + 1, now);
                    StateChanged();

                    _logger.Dump($"{Name}: temporarily banning {kvp.Key}, this is strike {strikes.Count + 1}", SeverityLevel.Info);
                }
            }
        }

        /// <summary>
        /// changes the settings of the running task (thread safe)
        /// </summary>
        internal void ApplySettings(bool active, int lockTime, int eventAge, int triggerCount, int permaBanCount)
        {
            lock (_syncObject)
            {
                Active = active;
                LockTime = lockTime;
                EventAge = eventAge;
                TriggerCount = triggerCount;
                PermaBanCount = permaBanCount;
            }
        }

        /// <summary>
        /// the current bans/trusts and strikes, so they survive a restart of the service
        /// </summary>
        internal TaskState ExportState()
        {
            lock (_syncObject)
            {
                return new TaskState(Name,
                    new Dictionary<IPAddress, DateTime>(_blockedIPsToDate),
                    new Dictionary<IPAddress, StrikeInfo>(_strikes));
            }
        }

        /// <summary>
        /// restores bans and strikes saved by <see cref="ExportState"/>; expired entries are dropped
        /// </summary>
        internal void ImportState(TaskState state)
        {
            if (state == null)
                return;

            lock (_syncObject)
            {
                DateTime now = DateTime.UtcNow;
                foreach (var ban in state.Bans)
                {
                    if (ban.Value.AddSeconds(LockTime) > now && ban.Value <= now.AddMinutes(5))
                    {
                        _blockedIPsToDate[ban.Key] = ban.Value;
                        // events from before the restart that led to this ban are not counted again
                        if (!IsTrustTask)
                            _ignoreEventsUntil[ban.Key] = ban.Value;
                    }
                }

                foreach (var strike in state.Strikes)
                {
                    if (strike.Value.Count > 0 && strike.Value.LastUtc > now - StrikeMemory)
                        _strikes[strike.Key] = strike.Value;
                }

                StateChanged();
            }
        }

        /// <summary>
        /// lifts a ban / revokes a trust and resets the strikes; the events seen so far are not counted again
        /// </summary>
        public void Forget(IPAddress address)
        {
            if (address == null)
                return;

            address = IPAddressTools.Normalize(address);

            lock (_syncObject)
            {
                _blockedIPsToDate.Remove(address);
                _ignoreEventsUntil[address] = DateTime.UtcNow;
                _strikes.Remove(address);
                StateChanged();
            }
        }

        #endregion
    }

    /// <summary>number of temporary bans of an IP and when the last one happened (UTC)</summary>
    internal struct StrikeInfo
    {
        public StrikeInfo(int count, DateTime lastUtc)
        {
            Count = count;
            LastUtc = lastUtc;
        }

        public int Count { get; }
        public DateTime LastUtc { get; }
    }
}
