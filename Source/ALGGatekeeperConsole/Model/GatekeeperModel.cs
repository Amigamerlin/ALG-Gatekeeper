using ALGGatekeeper.Contracts;
using ALGGatekeeper.Contracts.DTO;
using System;
using System.Collections.Generic;
using System.Net;
using System.ServiceModel;

namespace ALGGatekeeperConsole.Model
{
    /// <summary>
    /// Talks to the ALG Gatekeeper service over the local named pipe.
    /// One channel factory is reused; every call opens a short lived channel that is always closed (or aborted).
    /// </summary>
    public sealed class GatekeeperModel : IDisposable
    {
        #region private members

        private readonly object _syncObject = new object();
        private ChannelFactory<IGatekeeperService> _factory;
        private bool _disposed;

        #endregion

        #region public properties

        public IReadOnlyList<SeverityLevelDTO> ConsoleLevels { get; } = new List<SeverityLevelDTO>
        {
            SeverityLevelDTO.Off,
            SeverityLevelDTO.Debug,
            SeverityLevelDTO.Verbose,
            SeverityLevelDTO.Info,
            SeverityLevelDTO.Warning,
            SeverityLevelDTO.Error,
            SeverityLevelDTO.Critical
        }.AsReadOnly();

        #endregion

        #region public operations

        public bool IsServiceResponding() => Call(s => s.GetIsRunning());

        public string GetServiceVersion() => Call(s => s.GetServiceVersion());

        public GlobalConfigDTO GetGlobalConfig() => Call(s => s.GetGlobalConfig());

        public IPAddress[] GetTemporarilyBannedIPs() => ToAddresses(Call(s => s.GetTemporarilyBannedIPs()));

        public IPAddress[] GetPermanentlyBannedIPs() => ToAddresses(Call(s => s.GetPermanentlyBannedIPs()));

        public IPAddress[] GetTrustedIPs() => ToAddresses(Call(s => s.GetTrustedIPs()));

        public string[] GetWhiteListPatterns() => Call(s => s.GetWhiteListEntries()) ?? new string[0];

        /// <summary>console entries newer than <paramref name="afterId"/> (0 = all kept by the service)</summary>
        public IList<LogEntryDTO> GetConsoleHistory(long afterId) => Call(s => s.GetConsoleHistory(afterId)) ?? new List<LogEntryDTO>();

        public void AddWhiteListEntry(string pattern) => Call(s => s.AddWhiteListEntry(pattern));

        public void RemoveWhiteListEntry(string pattern) => Call(s => s.RemoveWhiteListEntry(pattern));

        public void AddPermanentIPBan(IPAddress address) => Call(s => s.SetPermanentBan(address));

        public void AddPermanentIPBans(IPAddress[] addresses) => Call(s => s.SetPermanentBans(addresses));

        public void RemovePermanentIPBan(IPAddress address) => Call(s => s.ClearPermanentBan(address));

        public void RemoveTemporaryBan(IPAddress address) => Call(s => s.RemoveTemporaryBan(address));

        public void RemoveTrust(IPAddress address) => Call(s => s.RemoveTrust(address));

        public void SaveGlobalConfig(SeverityLevelDTO logLevel, int consoleBackLog, int checkInterval, bool monitorOnly)
            => Call(s => s.SaveGlobalConfig(logLevel, consoleBackLog, checkInterval, monitorOnly));

        public void SaveTaskSettings(string taskName, bool active, int lockTime, int eventAge, int triggerCount, int permaBanCount)
            => Call(s => s.SaveTaskSettings(taskName, active, lockTime, eventAge, triggerCount, permaBanCount));

        public void Dispose()
        {
            lock (_syncObject)
            {
                if (_disposed)
                    return;

                _disposed = true;
                CloseFactory();
            }
        }

        #endregion

        #region private operations

        private static IPAddress[] ToAddresses(string[] list)
        {
            var result = new List<IPAddress>();
            foreach (string s in list ?? new string[0])
            {
                if (IPAddressTools.TryParseStrict(s, out IPAddress ip))
                    result.Add(ip);
            }
            return result.ToArray();
        }

        private ChannelFactory<IGatekeeperService> GetFactory()
        {
            lock (_syncObject)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(GatekeeperModel));

                if (_factory == null || _factory.State == CommunicationState.Faulted || _factory.State == CommunicationState.Closed)
                {
                    CloseFactory();
                    _factory = new ChannelFactory<IGatekeeperService>(ProductInfo.CreateBinding(), new EndpointAddress(ProductInfo.PipeAddress));
                }

                return _factory;
            }
        }

        private void CloseFactory()
        {
            if (_factory == null)
                return;

            try
            {
                if (_factory.State == CommunicationState.Faulted)
                    _factory.Abort();
                else
                    _factory.Close();
            }
            catch
            {
                _factory.Abort();
            }

            _factory = null;
        }

        private T Call<T>(Func<IGatekeeperService, T> operation)
        {
            IGatekeeperService channel = GetFactory().CreateChannel();
            var communicationObject = (ICommunicationObject)channel;
            bool closed = false;

            try
            {
                T result = operation(channel);
                communicationObject.Close();
                closed = true;
                return result;
            }
            finally
            {
                if (!closed)
                    communicationObject.Abort();
            }
        }

        private void Call(Action<IGatekeeperService> operation)
        {
            Call(s =>
            {
                operation(s);
                return true;
            });
        }

        #endregion
    }
}
