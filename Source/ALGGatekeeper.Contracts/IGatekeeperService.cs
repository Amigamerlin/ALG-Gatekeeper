using System.Collections.Generic;
using System.ServiceModel;
using System.Net;
using ALGGatekeeper.Contracts.DTO;

namespace ALGGatekeeper.Contracts
{
    /// <summary>
    /// The management interface of the ALG Gatekeeper service.
    /// It is only reachable on this machine (named pipe) and only by members of the local Administrators group.
    /// </summary>
    /// <remarks>
    /// Address lists are returned as strings: much smaller on the wire than serialized IPAddress objects,
    /// so even very long permanent ban lists fit easily into one message.
    /// </remarks>
    [ServiceContract]
    public interface IGatekeeperService
    {
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        GlobalConfigDTO GetGlobalConfig();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        bool GetIsRunning();

        /// <summary>
        /// the version of the running service
        /// </summary>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string GetServiceVersion();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetTemporarilyBannedIPs();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetPermanentlyBannedIPs();

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetPermanentBan(IPAddress address);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SetPermanentBans(IPAddress[] address);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void ClearPermanentBan(IPAddress address);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void AddWhiteListEntry(string filter);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void RemoveWhiteListEntry(string filter);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetWhiteListEntries();

        /// <summary>
        /// the console history; only entries with an Id greater than <paramref name="afterId"/> (0 = all)
        /// </summary>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        IList<LogEntryDTO> GetConsoleHistory(long afterId);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SaveGlobalConfig(SeverityLevelDTO logLevel, int consoleBackLog, int checkInterval, bool monitorOnly);

        /// <summary>
        /// IPs that logged in successfully and are therefore never banned (until their trust expires)
        /// </summary>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        string[] GetTrustedIPs();

        /// <summary>
        /// revokes the automatic trust of an IP
        /// </summary>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void RemoveTrust(IPAddress address);

        /// <summary>
        /// Changes the settings of one rule. They are saved to config.xml and take effect immediately.
        /// </summary>
        /// <param name="taskName">name of the rule</param>
        /// <param name="active">whether the rule is used</param>
        /// <param name="lockTime">ban duration in seconds</param>
        /// <param name="eventAge">observed time frame in seconds</param>
        /// <param name="triggerCount">failed attempts within the time frame that cause a temporary ban</param>
        /// <param name="permaBanCount">temporary bans that cause a permanent ban, -1 = never</param>
        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void SaveTaskSettings(string taskName, bool active, int lockTime, int eventAge, int triggerCount, int permaBanCount);

        [OperationContract]
        [FaultContract(typeof(ServiceFaultDTO))]
        void RemoveTemporaryBan(IPAddress address);
    }
}
