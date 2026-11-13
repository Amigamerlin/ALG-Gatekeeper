using System;

namespace ALGGatekeeper.Logging
{
    public class LogEntry
    {
        /// <summary>increasing number, lets the console fetch only new entries</summary>
        public long Id { get; set; }
        public DateTime Date { get; set; }
        public string Message { get; set; }
        public SeverityLevel Severity { get; set; }
    }
}
