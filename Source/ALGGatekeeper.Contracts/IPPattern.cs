using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace ALGGatekeeper.Contracts
{
    /// <summary>
    /// A white list entry. Supported forms:
    /// <list type="bullet">
    /// <item>a single address: 1.2.3.4 or 2001:db8::1</item>
    /// <item>wildcards (as in older versions): 192.168.* or 10.0.?.1</item>
    /// <item>CIDR networks: 192.168.0.0/16 or 2001:db8::/32</item>
    /// </list>
    /// </summary>
    public sealed class IPPattern
    {
        private static readonly Regex AllowedWildcardChars = new Regex(@"^[0-9a-fA-F\.:\*\?]+$", RegexOptions.CultureInvariant);

        private readonly Regex _wildcard;
        private readonly byte[] _network;
        private readonly int _prefixLength;
        private readonly AddressFamily _family;

        private IPPattern(string text, Regex wildcard)
        {
            Text = text;
            _wildcard = wildcard;
        }

        private IPPattern(string text, IPAddress network, int prefixLength)
        {
            Text = text;
            _network = network.GetAddressBytes();
            _prefixLength = prefixLength;
            _family = network.AddressFamily;
        }

        /// <summary>
        /// the pattern as entered by the user
        /// </summary>
        public string Text { get; }

        /// <summary>
        /// true if this is a CIDR network pattern
        /// </summary>
        public bool IsNetwork => _network != null;

        /// <summary>
        /// converts the old wildcard syntax to an anchored regex
        /// </summary>
        public static string WildcardToRegex(string pattern)
        {
            return "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        }

        /// <summary>
        /// Validates and parses a pattern. Use this for user input.
        /// </summary>
        public static bool TryParse(string pattern, out IPPattern result, out string error)
        {
            result = null;
            error = null;

            if (string.IsNullOrWhiteSpace(pattern))
            {
                error = "The pattern is empty.";
                return false;
            }

            pattern = pattern.Trim();

            if (pattern.Contains(";"))
            {
                error = "The pattern must not contain ';'.";
                return false;
            }

            int slash = pattern.IndexOf('/');
            if (slash >= 0)
            {
                string addressPart = pattern.Substring(0, slash);
                string prefixPart = pattern.Substring(slash + 1);

                if (!IPAddressTools.TryParseStrict(addressPart, out IPAddress network))
                {
                    error = $"'{addressPart}' is not a valid IP address.";
                    return false;
                }

                int maxPrefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                if (!int.TryParse(prefixPart, out int prefix) || prefix < 0 || prefix > maxPrefix)
                {
                    error = $"The network prefix must be a number between 0 and {maxPrefix}.";
                    return false;
                }

                result = new IPPattern(pattern, network, prefix);
                return true;
            }

            if (!AllowedWildcardChars.IsMatch(pattern))
            {
                error = "Only IP addresses, the wildcards * and ?, or CIDR networks (e.g. 192.168.0.0/16) are allowed.";
                return false;
            }

            result = new IPPattern(pattern, new Regex(WildcardToRegex(pattern), RegexOptions.CultureInvariant | RegexOptions.IgnoreCase));
            return true;
        }

        /// <summary>
        /// Parses a pattern loaded from an existing configuration.
        /// Never fails: entries that do not validate fall back to the old wildcard matching, as in previous versions.
        /// </summary>
        public static IPPattern ParseLenient(string pattern)
        {
            if (TryParse(pattern, out IPPattern result, out _))
                return result;

            return new IPPattern(pattern ?? string.Empty, new Regex(WildcardToRegex(pattern ?? string.Empty), RegexOptions.CultureInvariant | RegexOptions.IgnoreCase));
        }

        /// <summary>
        /// true if the address is covered by this pattern
        /// </summary>
        public bool IsMatch(IPAddress address)
        {
            if (address == null)
                return false;

            address = IPAddressTools.Normalize(address);

            if (_network == null)
                return _wildcard.IsMatch(address.ToString());

            if (address.AddressFamily != _family)
                return false;

            byte[] bytes = address.GetAddressBytes();
            int fullBytes = _prefixLength / 8;
            int remainingBits = _prefixLength % 8;

            for (int i = 0; i < fullBytes; i++)
            {
                if (bytes[i] != _network[i])
                    return false;
            }

            if (remainingBits > 0)
            {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                if ((bytes[fullBytes] & mask) != (_network[fullBytes] & mask))
                    return false;
            }

            return true;
        }

        public override string ToString() => Text;
    }
}
