using ALGGatekeeper.Contracts;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ALGGatekeeper.SystemAPI
{
    /// <summary>
    /// Wraps the parts of the "Windows Firewall with Advanced Security" COM API that ALG Gatekeeper needs.
    ///
    /// The COM objects (HNetCfg.FwPolicy2 / HNetCfg.FWRule) are used through late binding (dynamic),
    /// so no type library import (tlbimp / COMReference) is needed and the project builds with plain "dotnet build".
    ///
    /// Banned addresses are spread over several rules ("ALG Gatekeeper", "ALG Gatekeeper #2", ...) because a single
    /// firewall rule only accepts a limited number of remote addresses.
    /// </summary>
    public class FirewallAPI : IDisposable
    {
        #region constants

        /// <summary>
        /// the name of the first firewall rule
        /// </summary>
        public const string RuleName = ProductInfo.FirewallRuleName;

        /// <summary>
        /// how many addresses go into one firewall rule
        /// </summary>
        public const int MaxAddressesPerRule = 1000;

        /// <summary>
        /// safety limit when looking for leftover rules
        /// </summary>
        private const int MaxRules = 10000;

        /// <summary>
        /// rules are searched past missing numbers (e.g. "#2" deleted by hand while "#3" exists) until this many in a row are missing
        /// </summary>
        private const int MaxMissingInARow = 10;

        /// <summary>HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND): what INetFwRules::Item returns for a missing rule</summary>
        private const int HResultNotFound = unchecked((int)0x80070002);

        private const int NET_FW_IP_PROTOCOL_ANY = 256;
        private const int NET_FW_RULE_DIR_IN = 1;
        private const int NET_FW_ACTION_BLOCK = 0;
        private const int NET_FW_PROFILE2_ALL = 0x7FFFFFFF;

        /// <summary>domain (1) + private (2) + public (4): Windows may read "all profiles" back as just these bits</summary>
        private const int NET_FW_PROFILES_DOMAIN_PRIVATE_PUBLIC = 7;

        /// <summary>IPv4 ranges ("a-b") written back by the firewall are expanded up to this size for comparison</summary>
        private const long MaxRangeToExpand = 65536;

        private const string RuleDescription = "Rule managed by ALG Gatekeeper to block brute force attackers. It is enabled/disabled automatically, do not change it manually. Stopping the ALG Gatekeeper service removes it.";

        #endregion

        #region private members

        private dynamic _fwPolicy2;
        private bool _disposed;
        private readonly string _ruleName;

        #endregion

        #region .ctor

        /// <param name="ruleName">base name of the rules; only change it to clean up the rules of other programs (e.g. the legacy EvlWatcher rules)</param>
        public FirewallAPI(string ruleName = RuleName)
        {
            if (string.IsNullOrWhiteSpace(ruleName))
                throw new ArgumentException("A rule name is required.", nameof(ruleName));

            _ruleName = ruleName;
        }

        #endregion

        #region public static operations

        /// <summary>
        /// name of the n-th rule (0 based): "ALG Gatekeeper", "ALG Gatekeeper #2", "ALG Gatekeeper #3", ...
        /// </summary>
        public static string GetRuleName(string baseName, int index)
        {
            if (index < 0)
                throw new ArgumentOutOfRangeException(nameof(index));

            return index == 0 ? baseName : $"{baseName} #{index + 1}";
        }

        /// <summary>
        /// Format of a single address inside a rule's RemoteAddresses property.
        /// </summary>
        public static string ToFirewallAddress(IPAddress address)
        {
            address = IPAddressTools.Normalize(address);

            return address.AddressFamily == AddressFamily.InterNetwork
                ? address + "/255.255.255.255"
                : address.ToString();
        }

        /// <summary>
        /// Builds the RemoteAddresses strings for the rules: normalized, without duplicates,
        /// without addresses that must never be blocked, sorted, and split into chunks of <paramref name="chunkSize"/>.
        /// </summary>
        public static List<string> BuildRemoteAddressChunks(IEnumerable<IPAddress> addresses, int chunkSize = MaxAddressesPerRule)
        {
            if (chunkSize < 1)
                throw new ArgumentOutOfRangeException(nameof(chunkSize));

            List<IPAddress> clean = (addresses ?? Enumerable.Empty<IPAddress>())
                .Where(a => a != null)
                .Select(IPAddressTools.Normalize)
                .Where(IPAddressTools.IsBannable)
                .Distinct()
                .ToList();

            clean.Sort(IPAddressTools.Comparer);

            var chunks = new List<string>();
            for (int i = 0; i < clean.Count; i += chunkSize)
            {
                chunks.Add(string.Join(",", clean.Skip(i).Take(chunkSize).Select(ToFirewallAddress)));
            }

            return chunks;
        }

        #endregion

        #region private operations

        private dynamic GetPolicy2()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(FirewallAPI));

            if (_fwPolicy2 == null)
            {
                Type policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true);
                _fwPolicy2 = Activator.CreateInstance(policyType);
            }

            return _fwPolicy2;
        }

        /// <summary>
        /// returns the rule with the given name, or null if there is none.
        /// Only "not found" means null; any other error (firewall service restarting, access denied...) is thrown.
        /// </summary>
        private dynamic FindRule(string name)
        {
            try
            {
                return GetPolicy2().Rules.Item(name);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (COMException ex) when (ex.HResult == HResultNotFound)
            {
                return null;
            }
        }

        /// <summary>
        /// forgets the COM connection, so the next call starts with a fresh one (e.g. after the firewall service restarted)
        /// </summary>
        private void ResetPolicy()
        {
            if (_fwPolicy2 == null)
                return;

            try
            {
                Marshal.FinalReleaseComObject((object)_fwPolicy2);
            }
            catch
            {
                // already gone
            }
            _fwPolicy2 = null;
        }

        /// <summary>
        /// runs a firewall operation; on any error the COM connection is reset before the error is passed on
        /// </summary>
        private T Guarded<T>(Func<T> operation)
        {
            try
            {
                return operation();
            }
            catch
            {
                ResetPolicy();
                throw;
            }
        }

        /// <summary>
        /// calls <paramref name="action"/> for every existing rule from number <paramref name="firstIndex"/> on,
        /// skipping gaps of up to <see cref="MaxMissingInARow"/> missing numbers
        /// </summary>
        private void ForEachExistingRule(int firstIndex, Action<string, dynamic> action)
        {
            int missing = 0;
            for (int i = firstIndex; i < MaxRules && missing < MaxMissingInARow; i++)
            {
                string name = GetRuleName(_ruleName, i);
                dynamic rule = FindRule(name);
                if (rule == null)
                {
                    missing++;
                    continue;
                }

                missing = 0;
                action(name, rule);
            }
        }

        /// <summary>
        /// the entries of a RemoteAddresses value, normalized for comparison
        /// ("1.2.3.4/255.255.255.255", "1.2.3.4/32" and "1.2.3.4" are the same)
        /// </summary>
        private static long ToNumber(IPAddress v4)
        {
            byte[] b = v4.GetAddressBytes();
            return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
        }

        private static IPAddress FromNumber(long n) =>
            new IPAddress(new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n });

        internal static HashSet<string> ParseAddressList(string remoteAddresses)
        {
            var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string raw in (remoteAddresses ?? string.Empty).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string entry = raw.Trim();
                foreach (string suffix in new[] { "/255.255.255.255", "/32", "/128" })
                {
                    if (entry.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        entry = entry.Substring(0, entry.Length - suffix.Length);
                        break;
                    }
                }

                int dash = entry.IndexOf('-');
                if (dash > 0 &&
                    IPAddressTools.TryParseStrict(entry.Substring(0, dash), out IPAddress from) &&
                    IPAddressTools.TryParseStrict(entry.Substring(dash + 1), out IPAddress to) &&
                    from.AddressFamily == AddressFamily.InterNetwork && to.AddressFamily == AddressFamily.InterNetwork)
                {
                    // the firewall may merge neighbouring addresses into a range: compare address by address
                    long a = ToNumber(from), b = ToNumber(to);
                    if (b >= a && b - a < MaxRangeToExpand)
                    {
                        for (long n = a; n <= b; n++)
                            result.Add(FromNumber(n).ToString());
                        continue;
                    }
                }

                if (IPAddressTools.TryParseStrict(entry, out IPAddress ip))
                    entry = ip.ToString();

                result.Add(entry);
            }
            return result;
        }

        private dynamic CreateRule(string name)
        {
            Type ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", true);
            dynamic rule = Activator.CreateInstance(ruleType);

            rule.Name = name;
            rule.Description = RuleDescription;
            rule.Protocol = NET_FW_IP_PROTOCOL_ANY;
            rule.Direction = NET_FW_RULE_DIR_IN;
            rule.Action = NET_FW_ACTION_BLOCK;
            rule.Profiles = NET_FW_PROFILE2_ALL;
            rule.EdgeTraversal = false;
            rule.LocalAddresses = "*";
            // a new rule is always created DISABLED, it is only enabled after its remote addresses have been set
            rule.Enabled = false;

            GetPolicy2().Rules.Add(rule);

            return FindRule(name) ?? rule;
        }

        private void RemoveRule(string name)
        {
            GetPolicy2().Rules.Remove(name);
        }

        /// <summary>
        /// Puts the given addresses into the rule and enables it.
        /// Guarantees that a rule which would block "any" address is never left enabled.
        /// </summary>
        private bool ApplyChunk(dynamic rule, string remoteAddresses)
        {
            if (string.IsNullOrWhiteSpace(remoteAddresses))
                throw new ArgumentException("A block rule must never be enabled without remote addresses.", nameof(remoteAddresses));

            bool changed = false;

            // a rule found by name is only trusted after its essential properties are (re)set:
            // someone could have changed it to "Allow" or "Outbound" by hand
            if ((int)rule.Action != NET_FW_ACTION_BLOCK || (int)rule.Direction != NET_FW_RULE_DIR_IN ||
                (int)rule.Protocol != NET_FW_IP_PROTOCOL_ANY || ((int)rule.Profiles & NET_FW_PROFILES_DOMAIN_PRIVATE_PUBLIC) != NET_FW_PROFILES_DOMAIN_PRIVATE_PUBLIC)
            {
                if ((bool)rule.Enabled)
                    rule.Enabled = false;

                rule.Action = NET_FW_ACTION_BLOCK;
                rule.Direction = NET_FW_RULE_DIR_IN;
                rule.Protocol = NET_FW_IP_PROTOCOL_ANY;
                rule.Profiles = NET_FW_PROFILE2_ALL;
                changed = true;
            }

            // compared as sets: the firewall may store the list in its own order or notation
            if (!ParseAddressList((string)rule.RemoteAddresses).SetEquals(ParseAddressList(remoteAddresses)))
            {
                rule.RemoteAddresses = remoteAddresses;
                changed = true;
            }

            string effective = (string)rule.RemoteAddresses;
            if (string.IsNullOrWhiteSpace(effective) || effective.Trim() == "*")
            {
                // this would block the whole internet (including your own RDP session). Never do that.
                if ((bool)rule.Enabled)
                    rule.Enabled = false;

                throw new InvalidOperationException($"Firewall rule '{(string)rule.Name}' did not accept the address list, the rule was left disabled.");
            }

            if (!(bool)rule.Enabled)
            {
                rule.Enabled = true;
                changed = true;
            }

            return changed;
        }

        #endregion

        #region public operations

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Removes all rules of this program from the firewall.
        /// </summary>
        public void ClearIPBanList()
        {
            Guarded(() =>
            {
                var names = new List<string>();
                ForEachExistingRule(0, (name, rule) => names.Add(name));
                foreach (string name in names)
                    RemoveRule(name);
                return true;
            });
        }

        /// <summary>
        /// Makes the firewall block exactly the given addresses.
        /// </summary>
        /// <returns>true if something was changed in the firewall</returns>
        public bool AdjustIPBanList(IEnumerable<IPAddress> ips)
        {
            List<string> chunks = BuildRemoteAddressChunks(ips);

            return Guarded(() =>
            {
                bool changed = false;

                // 1. fill the needed rules
                for (int i = 0; i < chunks.Count; i++)
                {
                    string name = GetRuleName(_ruleName, i);
                    dynamic rule = FindRule(name);
                    if (rule == null)
                    {
                        rule = CreateRule(name);
                        changed = true;
                    }

                    if (ApplyChunk(rule, chunks[i]))
                        changed = true;
                }

                // 2. the first rule always stays (disabled when nothing is banned), as in previous versions
                if (chunks.Count == 0)
                {
                    dynamic first = FindRule(GetRuleName(_ruleName, 0)) ?? CreateRule(GetRuleName(_ruleName, 0));
                    if ((bool)first.Enabled)
                    {
                        // only disabled, never emptied: an enabled rule with an empty list would block everything
                        first.Enabled = false;
                        changed = true;
                    }
                }

                // 3. remove rules that are not needed anymore (also past gaps left by hand-deleted rules)
                var surplus = new List<string>();
                ForEachExistingRule(Math.Max(1, chunks.Count), (name, rule) => surplus.Add(name));
                foreach (string name in surplus)
                {
                    RemoveRule(name);
                    changed = true;
                }

                return changed;
            });
        }

        /// <summary>
        /// Returns the entries of all enabled rules of this program, as stored by the firewall
        /// (IPv4 addresses have the form "1.2.3.4/255.255.255.255").
        /// </summary>
        public List<string> GetBannedIPs()
        {
            return Guarded(() =>
            {
                var currentlyBannedIPs = new List<string>();

                ForEachExistingRule(0, (name, rule) =>
                {
                    if (!(bool)rule.Enabled)
                        return;

                    string remoteAddresses = (string)rule.RemoteAddresses;
                    if (string.IsNullOrWhiteSpace(remoteAddresses))
                        return;

                    foreach (string s in remoteAddresses.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
                        currentlyBannedIPs.Add(s.Contains("-") ? s.Split('-')[0] : s);
                });

                return currentlyBannedIPs;
            });
        }

        #endregion

        #region protected operations

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            // the COM object is only released explicitly; in the finalizer path the runtime cleans up the RCW by itself
            if (disposing)
                ResetPolicy();

            _disposed = true;
        }

        #endregion
    }
}
