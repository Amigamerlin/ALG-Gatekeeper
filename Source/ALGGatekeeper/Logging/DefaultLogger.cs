using ALGGatekeeper.Contracts;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace ALGGatekeeper.Logging
{
    /// <summary>
    /// Writes to the Windows event log (from LogLevel up) and keeps a history for the console.
    /// The history keeps Info and above always, Verbose/Debug only when LogLevel is set that low,
    /// so debug output (which contains whole events) costs nothing in normal operation.
    /// </summary>
    internal class DefaultLogger : ILogger
    {
        private const string EventSource = ProductInfo.EventSource;
        private const string EventLogName = "Application";

        /// <summary>the Windows event log refuses messages longer than 31839 characters</summary>
        private const int MaxEventLogMessageLength = 31000;

        private readonly object _syncObject = new object();
        private readonly bool _isInteractive = Environment.UserInteractive;
        private readonly Queue<LogEntry> _history = new Queue<LogEntry>();
        private int _historyMaxCount = SettingsLimits.DefaultConsoleBacklog;
        // starts at the current time in ms, so ids keep increasing across service restarts (the console only asks for newer ids)
        private long _lastId = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
        private bool _eventSourceChecked;

        public SeverityLevel LogLevel { get; set; } = SeverityLevel.Warning;

        public bool IsEnabled(SeverityLevel severity)
        {
            if (severity == SeverityLevel.Off)
                return false;

            return _isInteractive || severity >= SeverityLevel.Info || severity >= LogLevel;
        }

        public void Dump(string message, SeverityLevel severity)
        {
            if (!IsEnabled(severity))
                return;

            message = message ?? string.Empty;

            if (LogLevel != SeverityLevel.Off && severity >= LogLevel)
                WriteToEventLog(message, severity);

            var date = DateTime.Now;

            if (_isInteractive)
                Console.WriteLine($"{date:HH:mm:ss.fff} [{severity}] {message}");

            lock (_syncObject)
            {
                _history.Enqueue(new LogEntry { Id = ++_lastId, Message = message, Severity = severity, Date = date });
                TrimHistory();
            }
        }

        public void Dump(Exception e, SeverityLevel level = SeverityLevel.Error)
        {
            if (e == null)
                return;

            Dump(level >= SeverityLevel.Error ? e.ToString() : e.Message, level);
        }

        public IList<LogEntry> GetConsoleHistory(long afterId = 0)
        {
            lock (_syncObject)
            {
                return _history.Where(e => e.Id > afterId).ToList();
            }
        }

        public void SetConsoleHistoryMaxCount(int count)
        {
            lock (_syncObject)
            {
                _historyMaxCount = Math.Max(0, count);
                TrimHistory();
            }
        }

        private void TrimHistory()
        {
            while (_history.Count > _historyMaxCount)
                _history.Dequeue();
        }

        private void WriteToEventLog(string message, SeverityLevel severity)
        {
            try
            {
                if (!_eventSourceChecked)
                {
                    // needs admin rights the first time, so that the event source can be created
                    if (!EventLog.SourceExists(EventSource))
                        EventLog.CreateEventSource(EventSource, EventLogName);

                    _eventSourceChecked = true;
                }

                if (message.Length > MaxEventLogMessageLength)
                    message = message.Substring(0, MaxEventLogMessageLength) + " [...]";

                EventLog.WriteEntry(EventSource, message, ToEntryType(severity));
            }
            catch (Exception ex)
            {
                // logging must never take the service down
                if (_isInteractive)
                    Console.WriteLine($"Could not write to the event log: {ex.Message}");
            }
        }

        private static EventLogEntryType ToEntryType(SeverityLevel level)
        {
            switch (level)
            {
                case SeverityLevel.Warning:
                    return EventLogEntryType.Warning;
                case SeverityLevel.Info:
                case SeverityLevel.Verbose:
                case SeverityLevel.Debug:
                    return EventLogEntryType.Information;
                default:
                    return EventLogEntryType.Error;
            }
        }
    }
}
