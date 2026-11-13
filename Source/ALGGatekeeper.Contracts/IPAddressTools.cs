using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ALGGatekeeper.Contracts
{
    /// <summary>
    /// Helpers shared by the service and the console for dealing with IP addresses.
    /// </summary>
    public static class IPAddressTools
    {
        /// <summary>
        /// Name of the optional named regex group that holds the IP address.
        /// When a rule's regex has no group with this name, the first capture group is used.
        /// </summary>
        public const string IpGroupName = "ip";

        private static readonly Regex StrictIPv4 = new Regex(@"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", RegexOptions.CultureInvariant);

        /// <summary>
        /// Brings an address into a canonical form:
        /// IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) become plain IPv4 and the IPv6 scope id (%12) is dropped.
        /// </summary>
        public static IPAddress Normalize(IPAddress address)
        {
            if (address == null)
                return null;

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.IsIPv4MappedToIPv6)
                    return address.MapToIPv4();

                if (address.ScopeId != 0)
                    return new IPAddress(address.GetAddressBytes());
            }

            return address;
        }

        /// <summary>
        /// Strict parser: unlike <see cref="IPAddress.TryParse(string, out IPAddress)"/> it does not accept
        /// shortened IPv4 forms such as "10.1" or "12345", which regexes on log entries can easily produce by accident.
        /// The result is normalized.
        /// </summary>
        public static bool TryParseStrict(string value, out IPAddress address)
        {
            address = null;

            if (string.IsNullOrWhiteSpace(value))
                return false;

            value = value.Trim();

            // [2001:db8::1] -> 2001:db8::1
            if (value.Length > 2 && value[0] == '[' && value[value.Length - 1] == ']')
                value = value.Substring(1, value.Length - 2);

            if (value.IndexOf(':') < 0)
            {
                // must look like an IPv4 address with four octets
                if (!StrictIPv4.IsMatch(value))
                    return false;
            }

            if (!IPAddress.TryParse(value, out IPAddress parsed))
                return false;

            address = Normalize(parsed);
            return true;
        }

        /// <summary>
        /// Applies a rule regex to a log entry and extracts the attacker IP.
        /// Uses the group named "ip" when present, otherwise the first capture group.
        /// </summary>
        public static bool TryExtract(Regex regex, string input, out IPAddress address)
        {
            address = null;

            if (regex == null || input == null)
                return false;

            Match m = regex.Match(input);
            if (!m.Success)
                return false;

            Group g = m.Groups[IpGroupName];
            if (!g.Success)
            {
                if (m.Groups.Count < 2)
                    return false;
                g = m.Groups[1];
            }

            return g.Success && TryParseStrict(g.Value, out address);
        }

        /// <summary>
        /// False for addresses that must never end up in a block rule
        /// (unspecified, broadcast and loopback addresses).
        /// </summary>
        public static bool IsBannable(IPAddress address)
        {
            if (address == null)
                return false;

            address = Normalize(address);

            if (IPAddress.IsLoopback(address))
                return false;

            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.Broadcast) || address.Equals(IPAddress.IPv6Any))
                return false;

            return true;
        }

        /// <summary>
        /// Orders IPv4 before IPv6 and then numerically (so 10.0.0.9 comes before 10.0.0.10).
        /// </summary>
        public static int Compare(IPAddress x, IPAddress y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x == null) return -1;
            if (y == null) return 1;

            int family = ((int)x.AddressFamily).CompareTo((int)y.AddressFamily);
            if (family != 0)
                return family;

            byte[] a = x.GetAddressBytes();
            byte[] b = y.GetAddressBytes();

            int len = a.Length.CompareTo(b.Length);
            if (len != 0)
                return len;

            for (int i = 0; i < a.Length; i++)
            {
                int c = a[i].CompareTo(b[i]);
                if (c != 0)
                    return c;
            }

            return 0;
        }

        /// <summary>
        /// Comparer wrapper around <see cref="Compare(IPAddress, IPAddress)"/>.
        /// </summary>
        public static IComparer<IPAddress> Comparer { get; } = Comparer<IPAddress>.Create(Compare);
    }
}
