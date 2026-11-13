using ALGGatekeeper.Contracts;
using ALGGatekeeper.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Net;

namespace ALGGatekeeper.Tests
{
    /// <summary>
    /// The rules of the shipped config.xml against realistic events.
    /// </summary>
    [TestClass]
    public class RuleTests
    {
        private static IPAddress Extract(string taskName, string xml)
        {
            GenericIPBlockingTask task = TestData.LoadShippedTask(taskName);

            // the boosters must let the event through ...
            foreach (string booster in task.Boosters)
            {
                if (!xml.Contains(booster))
                    return null;
            }

            // ... and the regex must find the IP
            return IPAddressTools.TryExtract(task.Regex, xml, out IPAddress ip) ? ip : null;
        }

        [TestMethod]
        public void ShippedConfig_AllRulesLoad()
        {
            var logger = new TestLogger();
            var config = new Config.XmlServiceConfiguration(logger, TestData.ShippedConfigPath);
            config.Load();

            var tasks = config.TaskConfigurations.Select(c => GenericIPBlockingTask.FromConfiguration(c, logger)).ToList();

            Assert.AreEqual(14, tasks.Count);
            Assert.IsFalse(logger.Contains("skipped"), string.Join("\n", logger.Entries.Select(e => e.Message)));
            Assert.AreEqual(2, tasks.Count(t => t.IsTrustTask));
            Assert.IsTrue(tasks.All(t => t.Active));
            Assert.IsFalse(config.MonitorOnly);
            Assert.AreEqual(30, config.EventLogInterval);
            Assert.AreEqual(3000, config.ConsoleBackLog);
        }

        [TestMethod]
        public void Security4625_IPv4()
        {
            Assert.AreEqual("203.0.113.7", Extract("BlockRDPBrutersBySecurity4625", TestData.Failed4625("203.0.113.7"))?.ToString());
        }

        [TestMethod]
        public void Security4625_IPv6AndMapped()
        {
            Assert.AreEqual("2001:db8::7", Extract("BlockRDPBrutersBySecurity4625", TestData.Failed4625("2001:db8::7"))?.ToString());
            Assert.AreEqual("203.0.113.7", Extract("BlockRDPBrutersBySecurity4625", TestData.Failed4625("::ffff:203.0.113.7"))?.ToString());
        }

        [TestMethod]
        public void Security4625_NoAddress()
        {
            Assert.IsNull(Extract("BlockRDPBrutersBySecurity4625", TestData.Failed4625("-")));
        }

        [TestMethod]
        public void Security4625_DoesNotMatchSuccessfulLogon()
        {
            // the old booster "4625" also matched other events containing these digits
            string success = TestData.Success4624("203.0.113.7", 3).Replace("0x3e7", "0x4625");
            Assert.IsNull(Extract("BlockRDPBrutersBySecurity4625", success));
        }

        [TestMethod]
        public void TrustRdp_OnlyInteractiveRemoteLogons()
        {
            Assert.AreEqual("198.51.100.4", Extract("TrustRDPLogins", TestData.Success4624("198.51.100.4", 10))?.ToString());
            Assert.AreEqual("198.51.100.4", Extract("TrustRDPLogins", TestData.Success4624("198.51.100.4", 7))?.ToString());
            // network logons (type 3) can be anonymous: never trusted
            Assert.IsNull(Extract("TrustRDPLogins", TestData.Success4624("198.51.100.4", 3)));
            // a failed logon is never trusted
            Assert.IsNull(Extract("TrustRDPLogins", TestData.Failed4625("198.51.100.4")));
        }

        [TestMethod]
        public void RdpCore131_IPv4WithPort()
        {
            string xml = TestData.EventXml(131, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", ("ConnType", "TCP"), ("ClientIP", "203.0.113.50:51234"));
            Assert.AreEqual("203.0.113.50", Extract("BlockRDPBrutersByRdpCore131", xml)?.ToString());
            Assert.IsNull(Extract("BlockRDPBrutersByRdpCore131_IPV6", xml));
        }

        [TestMethod]
        public void RdpCore131_IPv6WithPort()
        {
            string xml = TestData.EventXml(131, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", ("ConnType", "TCP"), ("ClientIP", "[2001:db8::50]:51234"));
            Assert.AreEqual("2001:db8::50", Extract("BlockRDPBrutersByRdpCore131_IPV6", xml)?.ToString());
            Assert.IsNull(Extract("BlockRDPBrutersByRdpCore131", xml));

            string mapped = TestData.EventXml(131, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", ("ConnType", "TCP"), ("ClientIP", "[::ffff:203.0.113.50]:3389"));
            Assert.AreEqual("203.0.113.50", Extract("BlockRDPBrutersByRdpCore131_IPV6", mapped)?.ToString());
        }

        [TestMethod]
        public void RdpCore140()
        {
            string xml = TestData.EventXml(140, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", ("IPString", "203.0.113.51"));
            Assert.AreEqual("203.0.113.51", Extract("BlockRDPBrutersByRdpCore140", xml)?.ToString());
        }

        [TestMethod]
        public void SqlServer18456_AllReasons()
        {
            string wrongPassword = TestData.EventXml(18456, "MSSQLSERVER", (null, "sa"), (null, " Reason: Password did not match that for the login provided."), (null, " [CLIENT: 203.0.113.60]"));
            string unknownUser = TestData.EventXml(18456, "MSSQLSERVER", (null, "admin"), (null, " Reason: Could not find a login matching the name provided."), (null, " [CLIENT: 203.0.113.61]"));
            string local = TestData.EventXml(18456, "MSSQLSERVER", (null, "sa"), (null, " Reason: Password did not match that for the login provided."), (null, " [CLIENT: <local machine>]"));

            Assert.AreEqual("203.0.113.60", Extract("BlockMSSQLBruteforce", wrongPassword)?.ToString());
            Assert.AreEqual("203.0.113.61", Extract("BlockMSSQLBruteforce", unknownUser)?.ToString());
            Assert.IsNull(Extract("BlockMSSQLBruteforce", local));
        }

        [TestMethod]
        public void OpenSsh_FailedAndAccepted()
        {
            string failed = TestData.EventXml(4, "OpenSSH", ("process", "sshd"), ("payload", "Failed password for invalid user admin from 203.0.113.70 port 50122 ssh2"));
            string failedV6 = TestData.EventXml(4, "OpenSSH", ("process", "sshd"), ("payload", "Failed password for root from 2001:db8::70 port 50122 ssh2"));
            string accepted = TestData.EventXml(4, "OpenSSH", ("process", "sshd"), ("payload", "Accepted publickey for admin from 198.51.100.70 port 50123 ssh2: ED25519 SHA256:abc"));

            Assert.AreEqual("203.0.113.70", Extract("BlockSSHBrutersByOpenSsh", failed)?.ToString());
            Assert.AreEqual("2001:db8::70", Extract("BlockSSHBrutersByOpenSsh", failedV6)?.ToString());
            Assert.IsNull(Extract("BlockSSHBrutersByOpenSsh", accepted));
            Assert.AreEqual("198.51.100.70", Extract("TrustSSHLogins", accepted)?.ToString());
            Assert.IsNull(Extract("TrustSSHLogins", failed));
        }

        /// <summary>
        /// the attacker chooses the user name: an IP hidden in it must never be the one that gets banned
        /// </summary>
        [TestMethod]
        public void AttackerCannotChooseTheBannedIp()
        {
            string ssh = TestData.EventXml(4, "OpenSSH", ("process", "sshd"),
                ("payload", "Failed password for invalid user x from 8.8.8.8 port 22 ssh2 from 203.0.113.5 port 51234 ssh2"));
            Assert.AreEqual("203.0.113.5", Extract("BlockSSHBrutersByOpenSsh", ssh)?.ToString());

            string sshTrust = TestData.EventXml(4, "OpenSSH", ("process", "sshd"),
                ("payload", "Accepted password for x from 8.8.8.8 port 22 ssh2 from 203.0.113.6 port 51234 ssh2"));
            Assert.AreEqual("203.0.113.6", Extract("TrustSSHLogins", sshTrust)?.ToString());

            string maria = TestData.EventXml(100, "MariaDB", (null, "Access denied for user 'x'@'8.8.8.8' (using password'@'203.0.113.7' (using password: YES)"));
            Assert.AreEqual("203.0.113.7", Extract("MariaDB", maria)?.ToString());

            string sql = TestData.EventXml(18456, "MSSQLSERVER", (null, "x [CLIENT: 8.8.8.8]"),
                (null, " Reason: Password did not match that for the login provided."), (null, " [CLIENT: 203.0.113.8]"));
            Assert.AreEqual("203.0.113.8", Extract("BlockMSSQLBruteforce", sql)?.ToString());
        }

        [TestMethod]
        public void MariaDb_AnyUser()
        {
            string xml = TestData.EventXml(100, "MariaDB", (null, "Access denied for user 'wordpress'@'203.0.113.80' (using password: YES)"));
            Assert.AreEqual("203.0.113.80", Extract("MariaDB", xml)?.ToString());

            // in case the renderer escapes apostrophes
            Assert.AreEqual("203.0.113.81", Extract("MariaDB", xml.Replace("'", "&apos;").Replace("203.0.113.80", "203.0.113.81"))?.ToString());
        }

        [TestMethod]
        public void ExchangeAndVpn()
        {
            string exchange = TestData.EventXml(1035, "MSExchangeFrontEndTransport", (null, "LogonDenied"), (null, "Default Frontend SERVER01"), (null, "Ntlm"), (null, "203.0.113.90"));
            Assert.AreEqual("203.0.113.90", Extract("BlockSMTPAuthExchangeFrontend", exchange)?.ToString());

            string vpn = TestData.EventXml(6273, "Microsoft-Windows-Security-Auditing", ("SubjectUserName", "bob"), ("CallingStationID", "203.0.113.91"), ("Reason", "Authentication failed"));
            Assert.AreEqual("203.0.113.91", Extract("BlockVPNBrutersBySecurity6273", vpn)?.ToString());
        }
    }
}
