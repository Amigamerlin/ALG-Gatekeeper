using ALGGatekeeper.Contracts;
using ALGGatekeeper.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Xml.Linq;

namespace ALGGatekeeper.Config
{
    internal class XmlServiceConfiguration : IPersistentServiceConfiguration
    {
        #region private members

        private readonly object _syncObject = new object();

        private readonly List<IPAddress> _blacklistAddresses = new List<IPAddress>();
        private readonly HashSet<IPAddress> _blacklistSet = new HashSet<IPAddress>();
        private readonly List<string> _whiteListPatterns = new List<string>();
        private readonly List<IPersistentTaskConfiguration> _taskConfigurations = new List<IPersistentTaskConfiguration>();

        private volatile string[] _whitelistSnapshot = new string[0];
        private volatile IPAddress[] _blacklistSnapshot = new IPAddress[0];
        private volatile IPersistentTaskConfiguration[] _taskSnapshot = new IPersistentTaskConfiguration[0];

        private readonly ILogger _logger;
        private readonly string _configPath;
        private bool _inLoading = false;
        private int _consoleBacklog = SettingsLimits.DefaultConsoleBacklog;
        private int _eventLogInterval = SettingsLimits.DefaultCheckInterval;
        private bool _monitorOnly;

        #endregion

        #region public constructor

        /// <param name="logger">the logger</param>
        /// <param name="configPath">path of config.xml, defaults to the file next to the executable</param>
        public XmlServiceConfiguration(ILogger logger, string configPath = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configPath = configPath ?? XmlConfigFile.DefaultPath;
        }

        #endregion

        #region public properties

        public string ConfigPath => _configPath;

        public bool MonitorOnly
        {
            get
            {
                lock (_syncObject)
                    return _monitorOnly;
            }
            set
            {
                lock (_syncObject)
                {
                    if (_monitorOnly != value)
                    {
                        _monitorOnly = value;
                        if (!_inLoading)
                            WriteGlobalConfig("MonitorOnly", value ? "true" : "false");
                    }
                }
            }
        }

        public int EventLogInterval
        {
            get
            {
                lock (_syncObject)
                    return _eventLogInterval;
            }
            set
            {
                ValidateRange(value, SettingsLimits.MinCheckInterval, SettingsLimits.MaxCheckInterval, "The check interval");
                lock (_syncObject)
                {
                    if (_eventLogInterval != value)
                    {
                        _eventLogInterval = value;
                        if (!_inLoading)
                            WriteGlobalConfig("CheckInterval", value.ToString(CultureInfo.InvariantCulture));
                    }
                }
            }
        }

        // immutable snapshots: a new array after every change (callers may cache by reference)
        public IReadOnlyList<string> WhitelistPatterns => _whitelistSnapshot;

        public IReadOnlyList<IPAddress> BlacklistAddresses => _blacklistSnapshot;

        public IReadOnlyList<IPersistentTaskConfiguration> TaskConfigurations => _taskSnapshot;

        public SeverityLevel LogLevel
        {
            get
            {
                return _logger.LogLevel;
            }
            set
            {
                if (!Enum.IsDefined(typeof(SeverityLevel), value))
                    throw new ArgumentOutOfRangeException(nameof(value), $"Unknown log level {value}.");

                lock (_syncObject)
                {
                    if (_logger.LogLevel != value)
                    {
                        _logger.LogLevel = value;
                        if (!_inLoading)
                            WriteGlobalConfig("LogLevel", value.ToString());
                    }
                }
            }
        }

        public int ConsoleBackLog
        {
            get
            {
                lock (_syncObject)
                    return _consoleBacklog;
            }
            set
            {
                ValidateRange(value, 0, SettingsLimits.MaxConsoleBacklog, "The console backlog");
                lock (_syncObject)
                {
                    if (_consoleBacklog != value)
                    {
                        _consoleBacklog = value;
                        _logger.SetConsoleHistoryMaxCount(_consoleBacklog);
                        if (!_inLoading)
                            WriteGlobalConfig("ConsoleBacklog", value.ToString(CultureInfo.InvariantCulture));
                    }
                }
            }
        }

        #endregion

        #region public operations

        public bool AddWhiteListPattern(string pattern)
        {
            if (!IPPattern.TryParse(pattern, out IPPattern parsed, out string error))
                throw new ArgumentException(error, nameof(pattern));

            lock (_syncObject)
            {
                if (_whiteListPatterns.Contains(parsed.Text))
                    return false;

                _whiteListPatterns.Add(parsed.Text);
                _whitelistSnapshot = _whiteListPatterns.ToArray();
                WriteGlobalConfig("WhiteList", JoinList(_whiteListPatterns));
                return true;
            }
        }

        public bool RemoveWhiteListPattern(string pattern)
        {
            if (pattern == null)
                return false;

            lock (_syncObject)
            {
                if (!_whiteListPatterns.Remove(pattern) && !_whiteListPatterns.Remove(pattern.Trim()))
                    return false;

                _whitelistSnapshot = _whiteListPatterns.ToArray();
                WriteGlobalConfig("WhiteList", JoinList(_whiteListPatterns));
                return true;
            }
        }

        public int AddBlackListAddresses(IEnumerable<IPAddress> addresses)
        {
            if (addresses == null)
                return 0;

            lock (_syncObject)
            {
                int added = 0;
                foreach (IPAddress raw in addresses)
                {
                    IPAddress address = IPAddressTools.Normalize(raw);
                    if (!IPAddressTools.IsBannable(address) || !_blacklistSet.Add(address))
                        continue;

                    _blacklistAddresses.Add(address);
                    added++;
                }

                // written once for the whole batch, not once per address
                if (added > 0)
                {
                    _blacklistSnapshot = _blacklistAddresses.ToArray();
                    WriteGlobalConfig("Banlist", JoinList(_blacklistAddresses.Select(ip => ip.ToString())));
                }

                return added;
            }
        }

        public bool RemoveBlackListAddress(IPAddress address)
        {
            if (address == null)
                return false;

            address = IPAddressTools.Normalize(address);

            lock (_syncObject)
            {
                if (!_blacklistSet.Remove(address))
                    return false;

                _blacklistAddresses.Remove(address);
                _blacklistSnapshot = _blacklistAddresses.ToArray();
                WriteGlobalConfig("Banlist", JoinList(_blacklistAddresses.Select(ip => ip.ToString())));
                return true;
            }
        }

        public void Load()
        {
            LoadConfiguration();
        }

        #endregion

        #region private operations

        private static void ValidateRange(int value, int min, int max, string what)
        {
            if (value < min || value > max)
                throw new ArgumentOutOfRangeException(nameof(value), $"{what} must be between {min} and {max}, but is {value}.");
        }

        private static string JoinList(IEnumerable<string> items)
        {
            // same format as before: "a;b;c;"
            var list = items.ToList();
            return list.Count == 0 ? string.Empty : string.Join(";", list) + ";";
        }

        private void WriteGlobalConfig(string property, string value)
        {
            lock (_syncObject)
            {
                _logger.Dump($"Writing global config for: {property} = {value}", SeverityLevel.Verbose);

                XmlConfigFile.Update(_configPath, d =>
                {
                    XElement globalEl = XmlConfigFile.GetOrAdd(d.Root, "Global", addFirst: true);
                    XmlConfigFile.GetOrAdd(globalEl, property).Value = value ?? string.Empty;
                });
            }
        }

        private void LoadConfiguration()
        {
            lock (_syncObject)
            {
                try
                {
                    _inLoading = true;
                    XDocument d = XmlConfigFile.Load(_configPath);

                    if (d.Root == null)
                        throw new FormatException("config.xml has no root element.");

                    _logger.Dump($"now loading global settings from {_configPath}", SeverityLevel.Debug);
                    LoadGlobalSettings(d);
                    _logger.Dump($"finished loading global settings", SeverityLevel.Debug);

                    _logger.Dump($"now loading generic tasks", SeverityLevel.Debug);
                    LoadGenericTasks(d);
                    _logger.Dump($"finished loading generic tasks", SeverityLevel.Debug);
                }
                finally
                {
                    _inLoading = false;
                }
            }
        }

        private void LoadGenericTasks(XDocument d)
        {
            //clear in case of reload
            _taskConfigurations.Clear();
            _taskSnapshot = new IPersistentTaskConfiguration[0];

            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var taskNode in d.Descendants("Task"))
            {
                try
                {
                    var loadedTask = XmlTaskConfig.FromXmlElement(taskNode, _syncObject, _logger, _configPath);

                    if (!names.Add(loadedTask.TaskName))
                    {
                        _logger.Dump($"The task name \"{loadedTask.TaskName}\" is used more than once in config.xml, only the first one is used.", SeverityLevel.Warning);
                        continue;
                    }

                    _taskConfigurations.Add(loadedTask);
                    _logger.Dump($"loaded configuration for generic task \"{loadedTask.TaskName}\"({(loadedTask.Active ? "active" : "inactive")})", SeverityLevel.Debug);
                }
                catch (FormatException ex)
                {
                    // one broken task must not stop the protection given by all the others
                    _logger.Dump($"A task in config.xml was skipped because it is not valid: {ex.Message}", SeverityLevel.Error);
                }
            }

            _taskSnapshot = _taskConfigurations.ToArray();
        }

        private void LoadGlobalSettings(XDocument d)
        {
            XElement globalConfig = d.Root.Element("Global");

            if (globalConfig == null)
            {
                _logger.Dump("Global Service config could not be loaded", SeverityLevel.Critical);
                throw new FormatException("config.xml has no <Global> section.");
            }

            string logLevel = XmlConfigFile.GetValue(globalConfig, "LogLevel");
            if (!string.IsNullOrEmpty(logLevel))
            {
                if (Enum.TryParse(logLevel, true, out SeverityLevel level) && Enum.IsDefined(typeof(SeverityLevel), level))
                    LogLevel = level;
                else
                    _logger.Dump($"Unknown LogLevel '{logLevel}' in config.xml, keeping {LogLevel}.", SeverityLevel.Warning);
            }

            _logger.Dump($"Log level is set to : {LogLevel} ", SeverityLevel.Verbose);

            _eventLogInterval = ReadIntSetting(globalConfig, "CheckInterval", SettingsLimits.MinCheckInterval, SettingsLimits.MaxCheckInterval, SettingsLimits.DefaultCheckInterval);
            _logger.Dump($"Check interval is set to : {_eventLogInterval} s", SeverityLevel.Verbose);

            string monitorOnly = XmlConfigFile.GetValue(globalConfig, "MonitorOnly");
            if (string.IsNullOrEmpty(monitorOnly))
                _monitorOnly = false;
            else if (bool.TryParse(monitorOnly, out bool mo))
                _monitorOnly = mo;
            else
            {
                _monitorOnly = false;
                _logger.Dump($"<MonitorOnly> in config.xml must be true or false, but is '{monitorOnly}'. Using false.", SeverityLevel.Warning);
            }
            if (_monitorOnly)
                _logger.Dump("SIMULATION MODE is on: nobody will be banned, bans are only logged.", SeverityLevel.Info);

            _consoleBacklog = ReadIntSetting(globalConfig, "ConsoleBacklog", 0, SettingsLimits.MaxConsoleBacklog, SettingsLimits.DefaultConsoleBacklog);
            _logger.SetConsoleHistoryMaxCount(_consoleBacklog);
            _logger.Dump($"Console backlog is set to {_consoleBacklog}", SeverityLevel.Verbose);

            //clear in case of reload
            _blacklistAddresses.Clear();
            _blacklistSet.Clear();
            string banstring = XmlConfigFile.GetValue(globalConfig, "Banlist") ?? string.Empty;
            foreach (string ip in banstring.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (IPAddressTools.TryParseStrict(ip, out IPAddress address))
                {
                    if (_blacklistSet.Add(address))
                        _blacklistAddresses.Add(address);
                }
                else
                {
                    _logger.Dump($"Ignored invalid entry '{ip.Trim()}' in the Banlist of config.xml.", SeverityLevel.Warning);
                }
            }
            _logger.Dump($"Loaded permabanlist: {_blacklistAddresses.Count} entries", SeverityLevel.Verbose);

            _whiteListPatterns.Clear();
            string wstring = XmlConfigFile.GetValue(globalConfig, "WhiteList") ?? string.Empty;
            foreach (string rawPattern in wstring.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string ipPattern = rawPattern.Trim();
                if (ipPattern.Length == 0 || _whiteListPatterns.Contains(ipPattern))
                    continue;

                if (!IPPattern.TryParse(ipPattern, out _, out string error))
                    _logger.Dump($"White list entry '{ipPattern}' looks wrong ({error}). It is kept and matched as a wildcard pattern.", SeverityLevel.Warning);

                _whiteListPatterns.Add(ipPattern);
            }
            _logger.Dump($"Loaded whitelist: {wstring}", SeverityLevel.Verbose);

            _whitelistSnapshot = _whiteListPatterns.ToArray();
            _blacklistSnapshot = _blacklistAddresses.ToArray();
        }

        private int ReadIntSetting(XElement global, string name, int min, int max, int defaultValue)
        {
            string value = XmlConfigFile.GetValue(global, name);
            if (string.IsNullOrEmpty(value))
                return defaultValue;

            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result))
            {
                _logger.Dump($"<{name}> in config.xml must be a whole number, but is '{value}'. Using {defaultValue}.", SeverityLevel.Warning);
                return defaultValue;
            }

            if (result < min || result > max)
            {
                int clamped = Math.Max(min, Math.Min(max, result));
                _logger.Dump($"<{name}> in config.xml must be between {min} and {max}, but is {result}. Using {clamped}.", SeverityLevel.Warning);
                return clamped;
            }

            return result;
        }

        #endregion
    }
}
