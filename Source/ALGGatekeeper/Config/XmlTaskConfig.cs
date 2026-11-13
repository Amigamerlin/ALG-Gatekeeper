using ALGGatekeeper.Contracts;
using ALGGatekeeper.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml.Linq;

namespace ALGGatekeeper.Config
{
    internal class XmlTaskConfig : IPersistentTaskConfiguration
    {
        #region static

        internal static XmlTaskConfig FromXmlElement(XElement taskConfig, object syncObject, ILogger logger, string configPath)
        {
            if (taskConfig == null)
                throw new ArgumentNullException(nameof(taskConfig));

            string name = taskConfig.Attribute("Name")?.Value?.Trim();
            if (string.IsNullOrEmpty(name))
                throw new FormatException("A <Task> without a Name attribute was found in config.xml.");

            var newTask = new XmlTaskConfig(name, syncObject, logger, configPath);
            newTask._isLoading = true;
            try
            {
                newTask.Active = ReadBool(taskConfig.Attribute("Active")?.Value, name, "Active");
                newTask.Kind = ReadKind(taskConfig.Attribute("Type")?.Value, name);
                newTask.Description = XmlConfigFile.GetValue(taskConfig, "Description") ?? "<indescript Task>";
                newTask.LockTime = ReadInt(taskConfig, "LockTime", name, SettingsLimits.MinSeconds, SettingsLimits.MaxSeconds);
                newTask.OnlyNewEvents = ReadBool(XmlConfigFile.GetValue(taskConfig, "OnlyNew"), name, "OnlyNew");
                newTask.EventAge = ReadInt(taskConfig, "EventAge", name, SettingsLimits.MinSeconds, SettingsLimits.MaxSeconds);
                newTask.TriggerCount = ReadInt(taskConfig, "TriggerCount", name, SettingsLimits.MinTriggerCount, SettingsLimits.MaxTriggerCount);
                // negative = permanent bans disabled
                newTask.PermaBanCount = ReadInt(taskConfig, "PermaBanCount", name, int.MinValue, SettingsLimits.MaxPermaBanCount);
                newTask.EventPath = Require(taskConfig, "EventPath", name);
                newTask.Regex = Require(taskConfig, "Regex", name);

                XElement boosters = taskConfig.Element("RegexBoosters");
                if (boosters != null)
                {
                    foreach (var regexBoosterNode in boosters.Elements("Booster"))
                    {
                        // boosters are matched literally, surrounding whitespace from XML formatting is removed
                        string booster = regexBoosterNode.Value.Trim();
                        if (booster.Length > 0)
                            if (!newTask._regexBoosters.Contains(booster))
                                newTask._regexBoosters.Add(booster);
                    }
                }

                return newTask;
            }
            finally
            {
                newTask._isLoading = false;
            }
        }

        private static string Require(XElement task, string element, string taskName)
        {
            string value = XmlConfigFile.GetValue(task, element);
            if (string.IsNullOrEmpty(value))
                throw new FormatException($"Task {taskName}: <{element}> is missing or empty in config.xml.");
            return value;
        }

        private static int ReadInt(XElement task, string element, string taskName, int min, int max)
        {
            string value = Require(task, element, taskName);
            if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result))
                throw new FormatException($"Task {taskName}: <{element}> must be a whole number, but is '{value}'.");
            if (result < min || result > max)
                throw new FormatException($"Task {taskName}: <{element}> must be between {min} and {max}, but is {result}.");
            return result;
        }

        private static TaskKind ReadKind(string value, string taskName)
        {
            if (string.IsNullOrWhiteSpace(value))
                return TaskKind.Ban;

            if (Enum.TryParse(value.Trim(), true, out TaskKind kind) && Enum.IsDefined(typeof(TaskKind), kind))
                return kind;

            throw new FormatException($"Task {taskName}: Type must be 'Ban' or 'Trust', but is '{value}'.");
        }

        private static bool ReadBool(string value, string taskName, string element)
        {
            if (!bool.TryParse(value?.Trim(), out bool result))
                throw new FormatException($"Task {taskName}: {element} must be 'true' or 'false', but is '{value}'.");
            return result;
        }

        #endregion

        #region private members

        private readonly List<string> _regexBoosters = new List<string>();
        private bool _isLoading = false;
        private readonly object _syncObject;
        private readonly ILogger _logger;
        private readonly string _configPath;

        private string _description;
        private int _lockTime;
        private bool _onlyNewEvents;
        private int _eventAge;
        private int _triggerCount;
        private int _permaBanCount;
        private string _eventPath;
        private string _regex;
        private bool _active;

        #endregion

        #region private .ctor

        private XmlTaskConfig(string taskName, object syncObject, ILogger logger, string configPath)
        {
            TaskName = taskName ?? throw new ArgumentNullException(nameof(taskName));
            _syncObject = syncObject ?? new object();
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configPath = configPath ?? throw new ArgumentNullException(nameof(configPath));
        }

        #endregion

        #region private operations

        private void WriteTaskConfig(string property, string value, bool isAttribute = false)
        {
            lock (_syncObject)
            {
                _logger.Dump($"Writing task config for task {TaskName}: {property} = {value}", SeverityLevel.Verbose);

                XmlConfigFile.Update(_configPath, d =>
                {
                    XElement taskEl = XmlConfigFile.FindTask(d, TaskName);
                    if (isAttribute)
                        taskEl.SetAttributeValue(property, value);
                    else
                        XmlConfigFile.GetOrAdd(taskEl, property).Value = value ?? string.Empty;
                });
            }
        }

        private void Set<T>(ref T field, T value, string xmlName, Func<T, string> toXml)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
                return;

            field = value;
            if (!_isLoading)
                WriteTaskConfig(xmlName, toXml(value));
        }

        private static string IntToXml(int v) => v.ToString(CultureInfo.InvariantCulture);

        #endregion

        #region public properties

        public string Description
        {
            get => _description;
            set => Set(ref _description, value, "Description", v => v);
        }

        public int LockTime
        {
            get => _lockTime;
            set => Set(ref _lockTime, value, "LockTime", IntToXml);
        }

        public bool OnlyNewEvents
        {
            get => _onlyNewEvents;
            set => Set(ref _onlyNewEvents, value, "OnlyNew", v => v.ToString());
        }

        public int EventAge
        {
            get => _eventAge;
            set => Set(ref _eventAge, value, "EventAge", IntToXml);
        }

        public int TriggerCount
        {
            get => _triggerCount;
            set => Set(ref _triggerCount, value, "TriggerCount", IntToXml);
        }

        public int PermaBanCount
        {
            get => _permaBanCount;
            set => Set(ref _permaBanCount, value, "PermaBanCount", IntToXml);
        }

        public string EventPath
        {
            get => _eventPath;
            set => Set(ref _eventPath, value, "EventPath", v => v);
        }

        public IReadOnlyList<string> RegexBoosters => _regexBoosters;

        public string Regex
        {
            get => _regex;
            set => Set(ref _regex, value, "Regex", v => v);
        }

        public string TaskName { get; private set; }

        public TaskKind Kind { get; private set; } = TaskKind.Ban;

        public bool Active
        {
            get => _active;
            set
            {
                if (_active == value)
                    return;

                _active = value;
                if (!_isLoading)
                    WriteTaskConfig("Active", value ? "true" : "false", isAttribute: true);
            }
        }

        #endregion

        #region public operations

        public override string ToString()
        {
            return TaskName;
        }

        #endregion
    }
}
