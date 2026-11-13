using System.Collections.Generic;

namespace ALGGatekeeper.Contracts.DTO
{
    public class GlobalConfigDTO
    {
        /// <summary>
        /// Messages at or above this level will we written to the Log.
        /// </summary>
        public SeverityLevelDTO LogLevel { get; set; }

        /// <summary>
        /// this is the interval the log files should be checked, in seconds
        /// </summary>
        public int EventLogInterval { get; set; }

        /// <summary>
        /// simulation mode: the firewall is never changed, bans are only logged
        /// </summary>
        public bool MonitorOnly { get; set; }

        /// <summary>
        /// all configured generic Tasks
        /// </summary>
        public IList<GenericIPBlockingTaskDTO> GenericTaskConfigurations { get; set; }

        /// <summary>
        /// how many lines of console output will be provided by the wcf service (max)
        /// </summary>
        public int ConsoleBackLog
        {
            get; set;
        }
    }
}
