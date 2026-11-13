using System.Collections.Generic;

namespace ALGGatekeeper.Config
{
    /// <summary>
    /// what a task does with the IPs it finds
    /// </summary>
    public enum TaskKind
    {
        /// <summary>IPs found too often are banned (failed logins)</summary>
        Ban = 0,

        /// <summary>IPs found are trusted for LockTime seconds and are never banned meanwhile (successful logins)</summary>
        Trust = 1
    }

    /// <summary>
    /// The stored settings of one rule. Setting a property saves it to the configuration file.
    /// </summary>
    public interface IPersistentTaskConfiguration
    {
        /// <summary>the name of the task</summary>
        string TaskName { get; }

        /// <summary>Ban (default) or Trust, from the Type attribute of the task</summary>
        TaskKind Kind { get; }

        /// <summary>whether the task is active</summary>
        bool Active { get; set; }

        /// <summary>the description of the task</summary>
        string Description { get; set; }

        /// <summary>seconds a temporary ban (or the trust) lasts</summary>
        int LockTime { get; set; }

        /// <summary>true: every event is delivered only once instead of all events of the time frame</summary>
        bool OnlyNewEvents { get; set; }

        /// <summary>the time frame for the logs to be inspected, in seconds</summary>
        int EventAge { get; set; }

        /// <summary>how many violations trigger a temporary ban</summary>
        int TriggerCount { get; set; }

        /// <summary>how many temporary bans trigger a permanent ban, negative = never</summary>
        int PermaBanCount { get; set; }

        /// <summary>the event logs to be scanned, separated by comma</summary>
        string EventPath { get; set; }

        /// <summary>texts that must all be contained in an event before the regex is applied (for performance)</summary>
        IReadOnlyList<string> RegexBoosters { get; }

        /// <summary>the regex used to extract an attacker's IP address</summary>
        string Regex { get; set; }
    }
}
