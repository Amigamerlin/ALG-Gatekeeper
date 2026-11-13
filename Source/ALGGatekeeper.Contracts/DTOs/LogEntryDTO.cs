using System;


namespace ALGGatekeeper.Contracts.DTO
{
    public enum SeverityLevelDTO
    {
        Off = 6,
        Critical = 5,
        Error = 4,
        Warning = 3,
        Info = 2,
        Verbose = 1,
        Debug = 0
    };
    public class LogEntryDTO
    {
        /// <summary>increasing number of the entry</summary>
        public long Id { get; set; }
        public DateTime Date { get; set; }
        public string Message { get; set; }
        public SeverityLevelDTO Severity { get; set; }
    }
}
