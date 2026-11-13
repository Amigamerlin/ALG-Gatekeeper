using ALGGatekeeper.Logging;
using System.Collections.Generic;
using System.Net;

namespace ALGGatekeeper.Config
{
    /// <summary>
    /// The stored global settings. Setting a property saves it to the configuration file.
    /// The lists are immutable snapshots: a new instance is returned after every change,
    /// so callers can cache derived data as long as they get the same instance.
    /// </summary>
    public interface IPersistentServiceConfiguration
    {
        /// <summary>Messages at or above this level will be written to the Windows event log.</summary>
        SeverityLevel LogLevel { get; set; }

        /// <summary>simulation mode: everything works, but the firewall is never changed (bans are only logged)</summary>
        bool MonitorOnly { get; set; }

        /// <summary>the interval the logs are checked, in seconds</summary>
        int EventLogInterval { get; set; }

        /// <summary>how many lines of console output the service keeps for the console</summary>
        int ConsoleBackLog { get; set; }

        /// <summary>addresses/patterns which never get banned</summary>
        IReadOnlyList<string> WhitelistPatterns { get; }

        /// <summary>addresses which are always banned</summary>
        IReadOnlyList<IPAddress> BlacklistAddresses { get; }

        /// <summary>all configured rules</summary>
        IReadOnlyList<IPersistentTaskConfiguration> TaskConfigurations { get; }

        /// <summary>adds a pattern to the white list (throws ArgumentException when the pattern is not valid)</summary>
        /// <returns>true when the white list was changed</returns>
        bool AddWhiteListPattern(string pattern);

        /// <summary>removes a pattern from the white list</summary>
        /// <returns>true when the white list was changed</returns>
        bool RemoveWhiteListPattern(string pattern);

        /// <summary>adds ips to the blacklist; the configuration file is written once</summary>
        /// <returns>how many addresses were added</returns>
        int AddBlackListAddresses(IEnumerable<IPAddress> addresses);

        /// <summary>removes an ip from the black list</summary>
        /// <returns>true when the black list was changed</returns>
        bool RemoveBlackListAddress(IPAddress address);

        /// <summary>(re)loads the configuration file</summary>
        void Load();
    }
}
