using ALGGatekeeper.Config;
using ALGGatekeeper.Contracts;
using ALGGatekeeper.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Xml.Linq;

namespace ALGGatekeeper.Tasks
{
    /// <summary>
    /// the runtime state of one task: active temporary bans and strike counts
    /// </summary>
    internal sealed class TaskState
    {
        public TaskState(string taskName, Dictionary<IPAddress, DateTime> bans, Dictionary<IPAddress, StrikeInfo> strikes)
        {
            TaskName = taskName ?? throw new ArgumentNullException(nameof(taskName));
            Bans = bans ?? new Dictionary<IPAddress, DateTime>();
            Strikes = strikes ?? new Dictionary<IPAddress, StrikeInfo>();
        }

        public string TaskName { get; }

        /// <summary>ip -> UTC time the temporary ban (or the trust) started</summary>
        public Dictionary<IPAddress, DateTime> Bans { get; }

        /// <summary>ip -> number of temporary bans so far and the time of the last one</summary>
        public Dictionary<IPAddress, StrikeInfo> Strikes { get; }
    }

    /// <summary>
    /// Persists the task states in state.xml, so a restart, reboot or update of the service
    /// does not set banned attackers free or reset their strike count.
    /// </summary>
    internal static class TaskStateStore
    {
        public const string FileName = "state.xml";

        public static string DefaultPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);

        public static XDocument ToXml(IEnumerable<TaskState> states)
        {
            var root = new XElement("State", new XAttribute("Version", 1));

            foreach (TaskState state in states.Where(s => s != null).OrderBy(s => s.TaskName, StringComparer.Ordinal))
            {
                var taskEl = new XElement("Task", new XAttribute("Name", state.TaskName));

                foreach (var ban in state.Bans.OrderBy(b => b.Key, IPAddressTools.Comparer))
                {
                    taskEl.Add(new XElement("Ban",
                        new XAttribute("Ip", ban.Key.ToString()),
                        new XAttribute("Since", ToUtc(ban.Value).ToString("o", CultureInfo.InvariantCulture))));
                }

                foreach (var strike in state.Strikes.OrderBy(s => s.Key, IPAddressTools.Comparer))
                {
                    taskEl.Add(new XElement("Strike",
                        new XAttribute("Ip", strike.Key.ToString()),
                        new XAttribute("Count", strike.Value.Count.ToString(CultureInfo.InvariantCulture)),
                        new XAttribute("Last", ToUtc(strike.Value.LastUtc).ToString("o", CultureInfo.InvariantCulture))));
                }

                root.Add(taskEl);
            }

            return new XDocument(root);
        }

        public static Dictionary<string, TaskState> FromXml(XDocument document)
        {
            var result = new Dictionary<string, TaskState>(StringComparer.OrdinalIgnoreCase);
            if (document?.Root == null)
                return result;

            foreach (XElement taskEl in document.Root.Elements("Task"))
            {
                string name = ((string)taskEl.Attribute("Name"))?.Trim();
                if (string.IsNullOrEmpty(name) || result.ContainsKey(name))
                    continue;

                var bans = new Dictionary<IPAddress, DateTime>();
                foreach (XElement ban in taskEl.Elements("Ban"))
                {
                    if (IPAddressTools.TryParseStrict((string)ban.Attribute("Ip"), out IPAddress ip) &&
                        DateTime.TryParse((string)ban.Attribute("Since"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime since))
                    {
                        bans[ip] = ToUtc(since);
                    }
                }

                var strikes = new Dictionary<IPAddress, StrikeInfo>();
                foreach (XElement strike in taskEl.Elements("Strike"))
                {
                    if (IPAddressTools.TryParseStrict((string)strike.Attribute("Ip"), out IPAddress ip) &&
                        int.TryParse((string)strike.Attribute("Count"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int count) &&
                        count > 0)
                    {
                        // files without "Last" (none exist yet, but be tolerant): the strike counts from now
                        DateTime last = DateTime.TryParse((string)strike.Attribute("Last"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime l)
                            ? ToUtc(l)
                            : DateTime.UtcNow;
                        strikes[ip] = new StrikeInfo(count, last);
                    }
                }

                result.Add(name, new TaskState(name, bans, strikes));
            }

            return result;
        }

        private static DateTime ToUtc(DateTime value) =>
            value.Kind == DateTimeKind.Utc ? value : value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);

        public static Dictionary<string, TaskState> Load(string path, ILogger logger)
        {
            try
            {
                if (!File.Exists(path))
                    return new Dictionary<string, TaskState>(StringComparer.OrdinalIgnoreCase);

                return FromXml(XmlConfigFile.Load(path));
            }
            catch (Exception ex)
            {
                // a damaged state file must never stop the service; we simply start without the old bans
                logger?.Dump($"The saved ban state ({path}) could not be read and is ignored: {ex.Message}", SeverityLevel.Warning);
                return new Dictionary<string, TaskState>(StringComparer.OrdinalIgnoreCase);
            }
        }

        public static void Save(string path, XDocument document)
        {
            XmlConfigFile.Save(document, path);
        }
    }
}
