using ALGGatekeeper.SystemAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace ALGGatekeeper.Tests.Integration
{
    /// <summary>
    /// Talks to the real Windows Firewall: needs Windows and Administrator rights.
    /// Uses its own rule name, so a running ALG Gatekeeper is not disturbed.
    /// </summary>
    [TestClass]
    [DoNotParallelize]
    public class FirewallApiTests
    {
        private const string TestRuleName = "ALG Gatekeeper INTEGRATION TEST";
        private FirewallAPI _api;

        [TestInitialize]
        public void Init()
        {
            _api = new FirewallAPI(TestRuleName);
            _api.ClearIPBanList();
        }

        [TestCleanup]
        public void Cleanup()
        {
            _api.ClearIPBanList();
            _api.Dispose();
        }

        private static List<IPAddress> Ips(params string[] ips) => ips.Select(IPAddress.Parse).ToList();

        [TestMethod]
        public void EmptyList_RuleExistsButNothingIsBanned()
        {
            _api.AdjustIPBanList(new List<IPAddress>());
            Assert.AreEqual(0, _api.GetBannedIPs().Count);
        }

        [TestMethod]
        public void AddV4AndV6()
        {
            _api.AdjustIPBanList(Ips("192.0.2.15", "2001:db8::15", "192.0.2.16"));

            var banned = _api.GetBannedIPs();
            CollectionAssert.Contains(banned, "192.0.2.15/255.255.255.255");
            CollectionAssert.Contains(banned, "192.0.2.16/255.255.255.255");
            Assert.IsTrue(banned.Any(b => b.StartsWith("2001:db8::15")), string.Join(",", banned));
        }

        [TestMethod]
        public void SameListTwice_ReportsNoChange()
        {
            Assert.IsTrue(_api.AdjustIPBanList(Ips("192.0.2.20")));
            Assert.IsFalse(_api.AdjustIPBanList(Ips("192.0.2.20")));
        }

        [TestMethod]
        public void ClearingDisablesTheRule()
        {
            _api.AdjustIPBanList(Ips("192.0.2.30"));
            Assert.IsTrue(_api.AdjustIPBanList(new List<IPAddress>()));
            Assert.AreEqual(0, _api.GetBannedIPs().Count);
        }

        [TestMethod]
        public void LoopbackIsNeverBlocked()
        {
            _api.AdjustIPBanList(Ips("127.0.0.1", "::1"));
            Assert.AreEqual(0, _api.GetBannedIPs().Count);
        }

        [TestMethod]
        public void ManyAddresses_AreSplitOverSeveralRules_AndShrinkAgain()
        {
            var many = Enumerable.Range(0, 2100).Select(i => new IPAddress(new byte[] { 198, 18, (byte)(i / 256), (byte)(i % 256) })).ToList();

            _api.AdjustIPBanList(many);
            Assert.AreEqual(2100, _api.GetBannedIPs().Count);

            _api.AdjustIPBanList(many.Take(10).ToList());
            Assert.AreEqual(10, _api.GetBannedIPs().Count);
        }
    }
}
