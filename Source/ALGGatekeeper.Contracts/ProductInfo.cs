using System;
using System.ServiceModel;

namespace ALGGatekeeper.Contracts
{
    /// <summary>
    /// Names used by the service, the console and the installer. Change them only together with Installer/ALGGatekeeper.nsi.
    /// </summary>
    public static class ProductInfo
    {
        /// <summary>the name shown to users</summary>
        public const string DisplayName = "ALG Gatekeeper";

        /// <summary>the Windows service name (sc.exe, services.msc)</summary>
        public const string ServiceName = "ALGGatekeeper";

        /// <summary>the name of the firewall rules ("ALG Gatekeeper", "ALG Gatekeeper #2", ...)</summary>
        public const string FirewallRuleName = "ALG Gatekeeper";

        /// <summary>the source name in the Windows "Application" event log</summary>
        public const string EventSource = "ALG Gatekeeper";

        /// <summary>the name of the program ALG Gatekeeper is based on (used to migrate old installations)</summary>
        public const string LegacyName = "EvlWatcher";

        /// <summary>address of the local management endpoint</summary>
        public const string PipeBaseAddress = "net.pipe://localhost";
        public const string PipeEndpointName = "ALGGatekeeper";
        public static string PipeAddress => PipeBaseAddress + "/" + PipeEndpointName;

        /// <summary>
        /// The binding used on both sides. Named pipes are only reachable from the local machine;
        /// transport security (Windows authentication, signed and encrypted) is on.
        /// </summary>
        public static NetNamedPipeBinding CreateBinding()
        {
            const int maxSize = 16 * 1024 * 1024;

            var binding = new NetNamedPipeBinding(NetNamedPipeSecurityMode.Transport)
            {
                MaxReceivedMessageSize = maxSize,
                MaxBufferSize = maxSize,
                MaxBufferPoolSize = maxSize,
                OpenTimeout = TimeSpan.FromSeconds(10),
                SendTimeout = TimeSpan.FromSeconds(60),
                ReceiveTimeout = TimeSpan.FromMinutes(10),
                CloseTimeout = TimeSpan.FromSeconds(10)
            };

            binding.Security.Transport.ProtectionLevel = System.Net.Security.ProtectionLevel.EncryptAndSign;
            binding.ReaderQuotas.MaxArrayLength = maxSize;
            binding.ReaderQuotas.MaxStringContentLength = maxSize;
            binding.ReaderQuotas.MaxBytesPerRead = 64 * 1024;
            binding.ReaderQuotas.MaxDepth = 64;
            binding.ReaderQuotas.MaxNameTableCharCount = 64 * 1024;

            return binding;
        }
    }
}
