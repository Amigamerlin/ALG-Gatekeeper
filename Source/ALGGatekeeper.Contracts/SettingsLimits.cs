namespace ALGGatekeeper.Contracts
{
    /// <summary>
    /// Allowed ranges of all settings. Used by the service (to reject bad values)
    /// and by the console (to tell the user before sending).
    /// </summary>
    public static class SettingsLimits
    {
        /// <summary>check interval of the event logs, in seconds</summary>
        public const int MinCheckInterval = 1;
        public const int MaxCheckInterval = 3600;
        public const int DefaultCheckInterval = 30;

        /// <summary>lines of console history kept by the service</summary>
        public const int MinConsoleBacklog = 0;
        public const int MaxConsoleBacklog = 100000;
        public const int DefaultConsoleBacklog = 1000;

        /// <summary>LockTime (ban duration) and EventAge (observed time frame), in seconds; one year at most</summary>
        public const int MinSeconds = 1;
        public const int MaxSeconds = 365 * 24 * 3600;

        /// <summary>failed attempts within EventAge that cause a temporary ban</summary>
        public const int MinTriggerCount = 1;
        public const int MaxTriggerCount = 1000000;

        /// <summary>temporary bans that cause a permanent ban; a negative value disables permanent bans</summary>
        public const int MinPermaBanCount = -1;
        public const int MaxPermaBanCount = 1000000;

        /// <summary>
        /// returns null when the task settings are valid, otherwise an explanation
        /// </summary>
        public static string ValidateTaskSettings(int lockTime, int eventAge, int triggerCount, int permaBanCount)
        {
            if (lockTime < MinSeconds || lockTime > MaxSeconds)
                return $"The ban duration must be between {MinSeconds} and {MaxSeconds} seconds.";
            if (eventAge < MinSeconds || eventAge > MaxSeconds)
                return $"The observed time frame must be between {MinSeconds} and {MaxSeconds} seconds.";
            if (triggerCount < MinTriggerCount || triggerCount > MaxTriggerCount)
                return $"The number of attempts must be between {MinTriggerCount} and {MaxTriggerCount}.";
            if (permaBanCount > MaxPermaBanCount)
                return $"The number of temporary bans before a permanent ban must be at most {MaxPermaBanCount} (or -1 to never ban permanently).";
            return null;
        }
    }
}
