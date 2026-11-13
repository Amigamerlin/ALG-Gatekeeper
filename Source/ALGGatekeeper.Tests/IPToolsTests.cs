using ALGGatekeeper.Contracts;
using ALGGatekeeper.SystemAPI;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace ALGGatekeeper.Tests
{
    [TestClass]
    public class IPAddressToolsTests
    {
        [TestMethod]
        [DataRow("1.2.3.4", "1.2.3.4")]
        [DataRow(" 1.2.3.4 ", "1.2.3.4")]
        [DataRow("::ffff:1.2.3.4", "1.2.3.4")]
        [DataRow("[2001:db8::1]", "2001:db8::1")]
        [DataRow("fe80::1%12", "fe80::1")]
        [DataRow("2001:DB8::A", "2001:db8::a")]
        public void TryParseStrict_AcceptsAndNormalizes(string input, string expected)
        {
            Assert.IsTrue(IPAddressTools.TryParseStrict(input, out IPAddress ip));
            Assert.AreEqual(expected, ip.ToString());
        }

        [TestMethod]
        [DataRow("")]
        [DataRow("-")]
        [DataRow("1.2")]
        [DataRow("12345")]
        [DataRow("1.2.3")]
        [DataRow("1.2.3.4.5")]
        [DataRow("256.1.1.1")]
        [DataRow("hello")]
        [DataRow("1.2.3.4/24")]
        public void TryParseStrict_RejectsGarbage(string input)
        {
            Assert.IsFalse(IPAddressTools.TryParseStrict(input, out _));
        }

        [TestMethod]
        public void TryExtract_UsesNamedGroupFirst()
        {
            var regex = new Regex(@"(user \w+) from (?<ip>\S+)");
            Assert.IsTrue(IPAddressTools.TryExtract(regex, "login of user bob from 203.0.113.9 failed", out IPAddress ip));
            Assert.AreEqual("203.0.113.9", ip.ToString());
        }

        [TestMethod]
        public void TryExtract_FallsBackToFirstGroup_AndAllowsMoreGroups()
        {
            var regex = new Regex(@"from (\S+) port (\d+)");
            Assert.IsTrue(IPAddressTools.TryExtract(regex, "from 2001:db8::5 port 22", out IPAddress ip));
            Assert.AreEqual("2001:db8::5", ip.ToString());
        }

        [TestMethod]
        public void TryExtract_NoGroupOrNoMatch_IsFalse()
        {
            Assert.IsFalse(IPAddressTools.TryExtract(new Regex(@"\d+\.\d+\.\d+\.\d+"), "1.2.3.4", out _));
            Assert.IsFalse(IPAddressTools.TryExtract(new Regex(@"from (\S+)"), "nothing here", out _));
            Assert.IsFalse(IPAddressTools.TryExtract(new Regex(@"from (\S+)"), "from 1.2", out _));
        }

        [TestMethod]
        [DataRow("127.0.0.1", false)]
        [DataRow("::1", false)]
        [DataRow("0.0.0.0", false)]
        [DataRow("::", false)]
        [DataRow("255.255.255.255", false)]
        [DataRow("::ffff:127.0.0.1", false)]
        [DataRow("203.0.113.1", true)]
        [DataRow("2001:db8::1", true)]
        public void IsBannable(string ip, bool expected)
        {
            Assert.AreEqual(expected, IPAddressTools.IsBannable(IPAddress.Parse(ip)));
        }

        [TestMethod]
        public void Compare_SortsNumericallyAndV4BeforeV6()
        {
            var list = new[] { "10.0.0.10", "2001:db8::1", "10.0.0.9", "9.255.255.255" }.Select(IPAddress.Parse).ToList();
            list.Sort(IPAddressTools.Comparer);
            CollectionAssert.AreEqual(new[] { "9.255.255.255", "10.0.0.9", "10.0.0.10", "2001:db8::1" }, list.Select(i => i.ToString()).ToArray());
        }
    }

    [TestClass]
    public class IPPatternTests
    {
        [TestMethod]
        [DataRow("192.168.*", "192.168.44.3", true)]
        [DataRow("192.168.*", "192.169.0.1", false)]
        [DataRow("10.0.?.1", "10.0.5.1", true)]
        [DataRow("127.0.0.1", "127.0.0.1", true)]
        [DataRow("127.0.0.1", "127.0.0.10", false)]
        [DataRow("10.0.0.0/8", "10.200.1.1", true)]
        [DataRow("10.0.0.0/8", "11.0.0.1", false)]
        [DataRow("172.16.0.0/12", "172.31.255.255", true)]
        [DataRow("172.16.0.0/12", "172.32.0.0", false)]
        [DataRow("93.40.0.0/16", "93.40.255.1", true)]
        [DataRow("203.0.113.7/32", "203.0.113.7", true)]
        [DataRow("203.0.113.7/32", "203.0.113.8", false)]
        [DataRow("0.0.0.0/0", "8.8.8.8", true)]
        [DataRow("2001:db8::/32", "2001:db8:ffff::1", true)]
        [DataRow("2001:db8::/32", "2001:db9::1", false)]
        [DataRow("2001:DB8:*", "2001:db8:1::1", true)]
        [DataRow("10.0.0.0/8", "::ffff:10.1.1.1", true)]
        [DataRow("10.0.0.0/8", "2001:db8::1", false)]
        public void IsMatch(string pattern, string ip, bool expected)
        {
            Assert.IsTrue(IPPattern.TryParse(pattern, out IPPattern p, out string error), error);
            Assert.AreEqual(expected, p.IsMatch(IPAddress.Parse(ip)));
        }

        [TestMethod]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow("1.2.3.4;5.6.7.8")]
        [DataRow("10.0.0.0/33")]
        [DataRow("10.0.0.0/-1")]
        [DataRow("10.0.0.0/x")]
        [DataRow("2001:db8::/129")]
        [DataRow("hello")]
        [DataRow("1.2.3.4 ; drop")]
        public void TryParse_RejectsInvalid(string pattern)
        {
            Assert.IsFalse(IPPattern.TryParse(pattern, out _, out string error));
            Assert.IsFalse(string.IsNullOrEmpty(error));
        }

        [TestMethod]
        public void ParseLenient_KeepsOldEntries()
        {
            // an entry that does not validate still works as a wildcard, like in older versions
            IPPattern p = IPPattern.ParseLenient("server-*");
            Assert.IsFalse(p.IsMatch(IPAddress.Parse("1.2.3.4")));
            Assert.IsNotNull(IPPattern.ParseLenient(null));
        }
    }

    [TestClass]
    public class FirewallAddressTests
    {
        [TestMethod]
        public void RuleNames()
        {
            Assert.AreEqual("ALG Gatekeeper", FirewallAPI.GetRuleName(FirewallAPI.RuleName, 0));
            Assert.AreEqual("ALG Gatekeeper #2", FirewallAPI.GetRuleName(FirewallAPI.RuleName, 1));
            Assert.AreEqual("EvlWatcher #3", FirewallAPI.GetRuleName("EvlWatcher", 2));
        }

        [TestMethod]
        public void Chunks_AreCleanSortedAndFormatted()
        {
            var input = new[] { "203.0.113.10", "203.0.113.9", "::ffff:203.0.113.9", "127.0.0.1", "0.0.0.0", "2001:db8::1", "::1" }
                .Select(IPAddress.Parse);

            var chunks = FirewallAPI.BuildRemoteAddressChunks(input);

            Assert.AreEqual(1, chunks.Count);
            Assert.AreEqual("203.0.113.9/255.255.255.255,203.0.113.10/255.255.255.255,2001:db8::1", chunks[0]);
        }

        [TestMethod]
        public void Chunks_AreSplit()
        {
            var input = Enumerable.Range(1, 2500).Select(i => new IPAddress(new byte[] { 198, 18, (byte)(i / 256), (byte)(i % 256) }));
            var chunks = FirewallAPI.BuildRemoteAddressChunks(input, 1000);

            Assert.AreEqual(3, chunks.Count);
            Assert.AreEqual(1000, chunks[0].Split(',').Length);
            Assert.AreEqual(1000, chunks[1].Split(',').Length);
            Assert.AreEqual(500, chunks[2].Split(',').Length);
        }

        [TestMethod]
        public void AddressLists_AreComparedAsSets()
        {
            var a = FirewallAPI.ParseAddressList("203.0.113.9/255.255.255.255,2001:DB8::1,203.0.113.10/255.255.255.255");
            var b = FirewallAPI.ParseAddressList("203.0.113.10/32, 2001:db8::1/128 ,203.0.113.9");
            Assert.IsTrue(a.SetEquals(b));
            Assert.IsFalse(a.SetEquals(FirewallAPI.ParseAddressList("203.0.113.9/255.255.255.255")));

            // neighbouring addresses merged into a range by the firewall
            var merged = FirewallAPI.ParseAddressList("203.0.113.9-203.0.113.10,2001:db8::1");
            Assert.IsTrue(a.SetEquals(merged));
        }

        [TestMethod]
        public void Chunks_EmptyInput_NoChunks()
        {
            Assert.AreEqual(0, FirewallAPI.BuildRemoteAddressChunks(null).Count);
            Assert.AreEqual(0, FirewallAPI.BuildRemoteAddressChunks(new[] { IPAddress.Loopback }).Count);
        }
    }
}
