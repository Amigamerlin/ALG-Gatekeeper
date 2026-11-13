using ALGGatekeeper.Config;
using ALGGatekeeper.Logging;
using ALGGatekeeper.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Xml.Linq;

namespace ALGGatekeeper.Tests
{
    [TestClass]
    public class ConfigTests
    {
        private string _path;
        private TestLogger _logger;

        [TestInitialize]
        public void Init()
        {
            _path = TestData.CopyShippedConfig();
            _logger = new TestLogger();
        }

        [TestCleanup]
        public void Cleanup()
        {
            TestData.DeleteFolderOf(_path);
        }

        private XmlServiceConfiguration Load()
        {
            var c = new XmlServiceConfiguration(_logger, _path);
            c.Load();
            return c;
        }

        private void EditXml(Action<XDocument> edit)
        {
            XDocument d = XDocument.Load(_path, LoadOptions.PreserveWhitespace);
            edit(d);
            d.Save(_path);
        }

        [TestMethod]
        public void Changes_ArePersisted_AndKeepComments()
        {
            var c = Load();
            Assert.IsTrue(c.AddWhiteListPattern(" 93.40.0.0/16 "));
            Assert.IsFalse(c.AddWhiteListPattern("93.40.0.0/16"));
            Assert.AreEqual(2, c.AddBlackListAddresses(new[] { IPAddress.Parse("203.0.113.1"), IPAddress.Parse("::ffff:203.0.113.2"), IPAddress.Parse("203.0.113.1"), IPAddress.Loopback }));
            c.EventLogInterval = 15;
            c.MonitorOnly = true;

            var task = c.TaskConfigurations.Single(t => t.TaskName == "BlockRDPBrutersBySecurity4625");
            task.LockTime = 7200;
            task.Active = false;

            var reloaded = Load();
            CollectionAssert.Contains(reloaded.WhitelistPatterns.ToList(), "93.40.0.0/16");
            CollectionAssert.AreEquivalent(new[] { IPAddress.Parse("203.0.113.1"), IPAddress.Parse("203.0.113.2") }, reloaded.BlacklistAddresses.ToList());
            Assert.AreEqual(15, reloaded.EventLogInterval);
            Assert.IsTrue(reloaded.MonitorOnly);

            var task2 = reloaded.TaskConfigurations.Single(t => t.TaskName == "BlockRDPBrutersBySecurity4625");
            Assert.AreEqual(7200, task2.LockTime);
            Assert.IsFalse(task2.Active);

            string text = File.ReadAllText(_path);
            StringAssert.Contains(text, "SIMULATION MODE: true");
            Assert.IsFalse(File.Exists(_path + ".tmp"));
        }

        [TestMethod]
        public void InvalidWhiteListPattern_IsRejected()
        {
            var c = Load();
            Assert.ThrowsExactly<ArgumentException>(() => c.AddWhiteListPattern("not an ip"));
            Assert.ThrowsExactly<ArgumentException>(() => c.AddWhiteListPattern(""));
        }

        [TestMethod]
        public void OutOfRangeValues_AreRejected()
        {
            var c = Load();
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => c.EventLogInterval = 0);
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => c.ConsoleBackLog = -1);
        }

        [TestMethod]
        public void BrokenValuesInFile_AreClampedOrSkipped()
        {
            EditXml(d =>
            {
                XElement g = d.Root.Element("Global");
                g.Element("CheckInterval").Value = "0";
                g.Element("ConsoleBacklog").Value = "lots";
                g.Element("LogLevel").Value = "Chatty";
                g.Element("Banlist").Value = "203.0.113.1;garbage;1.2;";
                d.Descendants("Task").First().Element("TriggerCount").Value = "five";
            });

            var c = Load();
            Assert.AreEqual(1, c.EventLogInterval);
            Assert.AreEqual(1000, c.ConsoleBackLog);
            CollectionAssert.AreEqual(new[] { IPAddress.Parse("203.0.113.1") }, c.BlacklistAddresses.ToList());
            Assert.AreEqual(13, c.TaskConfigurations.Count(), "the broken task is skipped, all others load");
            Assert.IsTrue(_logger.Contains("skipped", SeverityLevel.Error));
        }

        [TestMethod]
        public void MissingGlobal_IsFatal()
        {
            EditXml(d => d.Root.Element("Global").Remove());
            Assert.ThrowsExactly<FormatException>(() => Load());
        }

        [TestMethod]
        public void Dtd_IsNotProcessed()
        {
            File.WriteAllText(_path, "<?xml version=\"1.0\"?><!DOCTYPE Config [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><Config><Global>&x;</Global></Config>");
            Assert.ThrowsExactly<System.Xml.XmlException>(() => Load());
        }

        [TestMethod]
        public void DuplicateTaskNames_FirstWins()
        {
            EditXml(d =>
            {
                XElement first = d.Descendants("Task").First();
                first.Parent.Add(new XElement(first));
            });

            Assert.AreEqual(14, Load().TaskConfigurations.Count());
            Assert.IsTrue(_logger.Contains("more than once", SeverityLevel.Warning));
        }
    }

    [TestClass]
    public class ConfigMigratorTests
    {
        private const string OldEvlWatcherConfig = @"<?xml version=""1.0"" encoding=""utf-8""?>
<Config>
  <Global>
    <LogLevel>Warning</LogLevel>
    <ConsoleBacklog>500</ConsoleBacklog>
    <CheckInterval>20</CheckInterval>
    <WhiteList>192.168.*;10.0.0.*;127.0.0.1;93.40.1.2;</WhiteList>
    <Banlist>203.0.113.1;203.0.113.2;garbage;</Banlist>
  </Global>
  <Tasks>
    <Task Name=""BlockRDPBrutersBySecurity4625"" Active=""false"">
      <Description>old</Description>
      <LockTime>7200</LockTime><OnlyNew>False</OnlyNew><EventAge>300</EventAge><TriggerCount>10</TriggerCount><PermaBanCount>-1</PermaBanCount>
      <EventPath>Security</EventPath>
      <RegexBoosters><Booster>4625</Booster></RegexBoosters>
      <Regex>&lt;Data Name=.IpAddress.&gt;(\d*.\d*.\d*.\d*)</Regex>
    </Task>
    <Task Name=""MyOwnRule"" Active=""true"">
      <Description>custom</Description>
      <LockTime>60</LockTime><OnlyNew>False</OnlyNew><EventAge>60</EventAge><TriggerCount>3</TriggerCount><PermaBanCount>3</PermaBanCount>
      <EventPath>Application</EventPath>
      <RegexBoosters><Booster>FAIL</Booster></RegexBoosters>
      <Regex>from (\S+)</Regex>
    </Task>
  </Tasks>
</Config>";

        [TestMethod]
        public void MigratesEvlWatcherConfig()
        {
            string newPath = TestData.CopyShippedConfig();
            string oldPath = Path.Combine(Path.GetDirectoryName(newPath), "old.xml");
            try
            {
                File.WriteAllText(oldPath, OldEvlWatcherConfig);
                string report = ConfigMigrator.Migrate(oldPath, newPath);
                StringAssert.Contains(report, "MyOwnRule");

                var logger = new TestLogger();
                var c = new XmlServiceConfiguration(logger, newPath);
                c.Load();

                Assert.AreEqual(SeverityLevel.Warning, c.LogLevel);
                Assert.AreEqual(20, c.EventLogInterval);
                Assert.AreEqual(500, c.ConsoleBackLog);

                // lists are merged: the user's entries and the new defaults
                var white = c.WhitelistPatterns.ToList();
                CollectionAssert.IsSubsetOf(new[] { "192.168.*", "93.40.1.2", "10.0.0.0/8", "172.16.0.0/12" }, white);
                Assert.AreEqual(white.Count, white.Distinct().Count());
                CollectionAssert.AreEquivalent(new[] { IPAddress.Parse("203.0.113.1"), IPAddress.Parse("203.0.113.2") }, c.BlacklistAddresses.ToList());

                // known task: new definition, user's tuning
                var t = c.TaskConfigurations.Single(x => x.TaskName == "BlockRDPBrutersBySecurity4625");
                Assert.IsFalse(t.Active);
                Assert.AreEqual(7200, t.LockTime);
                Assert.AreEqual(300, t.EventAge);
                Assert.AreEqual(10, t.TriggerCount);
                Assert.AreEqual(-1, t.PermaBanCount);
                StringAssert.Contains(t.Regex, "(?<ip>");

                // custom task carried over, new trust rules present
                Assert.IsTrue(c.TaskConfigurations.Any(x => x.TaskName == "MyOwnRule"));
                Assert.IsTrue(c.TaskConfigurations.Any(x => x.TaskName == "TrustRDPLogins" && x.Kind == TaskKind.Trust && x.Active));
                Assert.AreEqual(15, c.TaskConfigurations.Count());
                Assert.IsFalse(logger.Contains("skipped"));
            }
            finally
            {
                TestData.DeleteFolderOf(newPath);
            }
        }

        [TestMethod]
        public void MigratingTwice_ChangesNothing()
        {
            string newPath = TestData.CopyShippedConfig();
            string oldPath = Path.Combine(Path.GetDirectoryName(newPath), "old.xml");
            try
            {
                File.WriteAllText(oldPath, OldEvlWatcherConfig);
                ConfigMigrator.Migrate(oldPath, newPath);
                string once = File.ReadAllText(newPath);
                ConfigMigrator.Migrate(oldPath, newPath);
                Assert.AreEqual(once, File.ReadAllText(newPath));
            }
            finally
            {
                TestData.DeleteFolderOf(newPath);
            }
        }
    }

    [TestClass]
    public class TaskStateStoreTests
    {
        [TestMethod]
        public void RoundTrip()
        {
            var since = new DateTime(2026, 11, 13, 10, 0, 0, DateTimeKind.Utc);
            var states = new[]
            {
                new TaskState("A", new Dictionary<IPAddress, DateTime> { [IPAddress.Parse("203.0.113.1")] = since, [IPAddress.Parse("2001:db8::1")] = since },
                                   new Dictionary<IPAddress, StrikeInfo> { [IPAddress.Parse("203.0.113.1")] = new StrikeInfo(2, since) }),
                new TaskState("B", null, null)
            };

            var loaded = TaskStateStore.FromXml(TaskStateStore.ToXml(states));

            Assert.AreEqual(2, loaded.Count);
            Assert.AreEqual(since, loaded["a"].Bans[IPAddress.Parse("2001:db8::1")]);
            Assert.AreEqual(2, loaded["A"].Strikes[IPAddress.Parse("203.0.113.1")].Count);
            Assert.AreEqual(since, loaded["A"].Strikes[IPAddress.Parse("203.0.113.1")].LastUtc);
            Assert.AreEqual(DateTimeKind.Utc, loaded["a"].Bans[IPAddress.Parse("2001:db8::1")].Kind);
            Assert.AreEqual(0, loaded["B"].Bans.Count);
        }

        [TestMethod]
        public void DamagedFile_IsIgnored()
        {
            string path = Path.Combine(Path.GetTempPath(), "algstate_" + Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                File.WriteAllText(path, "<State><Task Name=");
                var logger = new TestLogger();
                Assert.AreEqual(0, TaskStateStore.Load(path, logger).Count);
                Assert.IsTrue(logger.Contains("ignored", SeverityLevel.Warning));

                Assert.AreEqual(0, TaskStateStore.Load(path + ".missing", logger).Count);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [TestMethod]
        public void InvalidEntries_AreSkipped()
        {
            var doc = XDocument.Parse("<State><Task Name='A'><Ban Ip='nonsense' Since='2026-01-01T00:00:00Z'/><Ban Ip='203.0.113.1' Since='yesterday'/><Strike Ip='203.0.113.1' Count='-3'/></Task></State>");
            var loaded = TaskStateStore.FromXml(doc);
            Assert.AreEqual(0, loaded["A"].Bans.Count);
            Assert.AreEqual(0, loaded["A"].Strikes.Count);
        }
    }
}
