using System;
using System.Collections.Generic;

namespace ALGGatekeeper.Logging
{
    public enum SeverityLevel
    {
        Off = 6,
        Critical = 5,
        Error = 4,
        Warning = 3,
        Info = 2,
        Verbose = 1,
        Debug = 0
    };

    public interface ILogger
    {
        /// <summary>messages at or above this level are written to the Windows event log</summary>
        SeverityLevel LogLevel { get; set; }

        /// <summary>
        /// false if a message of this level would be thrown away anyway.
        /// Check it before building expensive messages (e.g. with the XML of an event).
        /// </summary>
        bool IsEnabled(SeverityLevel severity);

        void Dump(string message, SeverityLevel severity);
        void Dump(Exception e, SeverityLevel severity = SeverityLevel.Error);

        void SetConsoleHistoryMaxCount(int count);

        /// <summary>the kept console history, only entries with an Id greater than <paramref name="afterId"/></summary>
        IList<LogEntry> GetConsoleHistory(long afterId = 0);
    }
}
