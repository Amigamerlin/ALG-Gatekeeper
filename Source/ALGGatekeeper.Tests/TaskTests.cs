using ALGGatekeeper.Config;
using ALGGatekeeper.Logging;
using ALGGatekeeper.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace ALGGatekeeper.Tests
{
    [TestClass]
    public class GenericTaskTests
    {
        private static GenericIPBlockingTask NewTask(TestLogger logger, TaskKind kind = TaskKind.Ban, int trigger = 3, int perma = 2)
        {
            return new GenericIPBlockingTask(logger)
            {
                Name = "TestRule",
                Active = true,
                Kind = kind,
                LockTime = 3600,
                TriggerCount = trigger,
                PermaBanCount = perma,
                Boosters = new List<string> { "LOGIN FAILED" },
                Regex = new Regex(@"from (?<ip>[0-9a-fA-F:.]+)", RegexOptions.None, GenericIPBlockingTask.RegexTimeout)
            };
        }

        [TestMethod]
        public void BansOnlyAtTriggerCount()
        {
            var task = NewTask(new TestLogger());

            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.1", 2));
            Assert.AreEqual(0, task.GetTempBanVictims().Count);

            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.1", 3));
            CollectionAssert.AreEqual(new[] { IPAddress.Parse("203.0.113.1") }, task.GetTempBanVictims());
        }

        [TestMethod]
        public void BoostersFilterEvents()
        {
            var task = NewTask(new TestLogger());
            task.ProvideEvents(TestData.Repeat("LOGIN OK from 203.0.113.1", 10));
            Assert.AreEqual(0, task.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void PermanentAfterStrikes()
        {
            var task = NewTask(new TestLogger(), perma: 2);
            var ip = IPAddress.Parse("203.0.113.2");

            // strike 1
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.2", 3));
            Assert.AreEqual(0, task.GetPermaBanVictims().Count);

            // the temporary ban expires ...
            task.LockTime = 0;
            System.Threading.Thread.Sleep(5);
            Assert.AreEqual(0, task.GetTempBanVictims().Count);

            // ... the attacker comes back (new events): strike 2 = permanent
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.2", 3).Select(e => { e.TimeCreated = DateTime.UtcNow; return e; }).ToList());
            CollectionAssert.AreEqual(new[] { ip }, task.GetPermaBanVictims());

            // strikes are reset after the permanent ban was handed out
            Assert.AreEqual(0, task.GetPermaBanVictims().Count);
        }

        [TestMethod]
        public void SameEvents_NeverCauseASecondBan()
        {
            // LockTime shorter than the time frame: after the ban expires the same old events are delivered again
            var task = NewTask(new TestLogger(), perma: 2);
            var events = TestData.Repeat("LOGIN FAILED from 203.0.113.30", 3);

            task.ProvideEvents(events);
            task.LockTime = 0;
            System.Threading.Thread.Sleep(5);
            Assert.AreEqual(0, task.GetTempBanVictims().Count);

            task.ProvideEvents(events);
            Assert.AreEqual(0, task.GetTempBanVictims().Count, "old events must not ban again");
            Assert.AreEqual(1, task.ExportState().Strikes.Single().Value.Count, "and must not add a strike");
        }

        [TestMethod]
        public void Strikes_ExpireAfterAQuietMonth()
        {
            var task = NewTask(new TestLogger(), perma: 2);
            task.ImportState(new TaskState("t", null, new Dictionary<IPAddress, StrikeInfo>
            {
                [IPAddress.Parse("203.0.113.31")] = new StrikeInfo(1, DateTime.UtcNow - GenericIPBlockingTask.StrikeMemory + TimeSpan.FromSeconds(1))
            }));
            Assert.AreEqual(1, task.ExportState().Strikes.Count);

            System.Threading.Thread.Sleep(1100);
            task.GetTempBanVictims();
            Assert.AreEqual(0, task.ExportState().Strikes.Count);
        }

        [TestMethod]
        public void Forget_ResetsStrikes()
        {
            var task = NewTask(new TestLogger(), perma: 2);
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.6", 3));
            task.Forget(IPAddress.Parse("203.0.113.6"));
            Assert.AreEqual(0, task.ExportState().Strikes.Count);
            Assert.AreEqual(0, task.ExportState().Bans.Count);
        }

        [TestMethod]
        public void PermanentBan_LogsTheIpNotTheCount()
        {
            var logger = new TestLogger();
            var task = NewTask(logger, perma: 1);
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.3", 3));

            CollectionAssert.AreEqual(new[] { IPAddress.Parse("203.0.113.3") }, task.GetPermaBanVictims());
            Assert.IsTrue(logger.Contains("permanently banned 203.0.113.3"));
        }

        [TestMethod]
        public void NegativePermaBanCount_NeverPermanent()
        {
            var task = NewTask(new TestLogger(), perma: -1);
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.4", 30));
            Assert.AreEqual(0, task.GetPermaBanVictims().Count);
            Assert.AreEqual(1, task.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void Forget_IgnoresOldEventsOfThatIp()
        {
            var task = NewTask(new TestLogger());
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.5", 3));
            task.Forget(IPAddress.Parse("203.0.113.5"));

            // the same (old) events are delivered again in the next cycle: must not ban again
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.5", 3));
            Assert.AreEqual(0, task.GetTempBanVictims().Count);
        }

        [TestMethod]
        public void TrustTask_TrustsAndNeverPermaBans()
        {
            var logger = new TestLogger();
            var task = NewTask(logger, TaskKind.Trust, trigger: 1, perma: 0);
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 198.51.100.1", 1));

            CollectionAssert.AreEqual(new[] { IPAddress.Parse("198.51.100.1") }, task.GetTempBanVictims());
            Assert.AreEqual(0, task.GetPermaBanVictims().Count);
            Assert.IsTrue(logger.Contains("is trusted"));
        }

        [TestMethod]
        public void TrustTask_RenewsOnEveryLogin()
        {
            var task = NewTask(new TestLogger(), TaskKind.Trust, trigger: 1);
            var ip = IPAddress.Parse("198.51.100.2");

            task.ImportState(new TaskState("t", new Dictionary<IPAddress, DateTime> { [ip] = DateTime.UtcNow.AddSeconds(-3590) }, null));
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 198.51.100.2", 1));

            DateTime since = task.ExportState().Bans[ip];
            Assert.IsTrue(since > DateTime.UtcNow.AddMinutes(-1), "trust must be renewed");
        }

        [TestMethod]
        public void ImportState_DropsExpiredAndFutureBans()
        {
            var task = NewTask(new TestLogger());
            var bans = new Dictionary<IPAddress, DateTime>
            {
                [IPAddress.Parse("203.0.113.10")] = DateTime.UtcNow.AddMinutes(-10),   // valid
                [IPAddress.Parse("203.0.113.11")] = DateTime.UtcNow.AddHours(-2),      // expired (LockTime 1h)
                [IPAddress.Parse("203.0.113.12")] = DateTime.UtcNow.AddDays(1)         // clock nonsense
            };
            task.ImportState(new TaskState("t", bans, new Dictionary<IPAddress, StrikeInfo>
            {
                [IPAddress.Parse("203.0.113.13")] = new StrikeInfo(1, DateTime.UtcNow.AddDays(-1)),   // kept
                [IPAddress.Parse("203.0.113.14")] = new StrikeInfo(2, DateTime.UtcNow.AddDays(-40))   // expired
            }));

            CollectionAssert.AreEqual(new[] { IPAddress.Parse("203.0.113.10") }, task.GetTempBanVictims());
            Assert.AreEqual(1, task.ExportState().Strikes.Count);
        }

        [TestMethod]
        public void ApplySettings_ChangesRunningTask()
        {
            var task = NewTask(new TestLogger(), trigger: 10);
            task.ApplySettings(true, 60, 300, 2, -1);
            task.ProvideEvents(TestData.Repeat("LOGIN FAILED from 203.0.113.20", 2));

            Assert.AreEqual(1, task.GetTempBanVictims().Count);
            Assert.AreEqual(300, task.EventAge);
            Assert.AreEqual(60, task.LockTime);
        }

        [TestMethod]
        public void SlowRegex_IsAbortedAndReported()
        {
            var logger = new TestLogger();
            var task = new GenericIPBlockingTask(logger)
            {
                Name = "SlowRule",
                TriggerCount = 1,
                // catastrophic backtracking on purpose
                Regex = new Regex(@"^(a+)+(?<ip>\d+\.\d+\.\d+\.\d+)$", RegexOptions.None, TimeSpan.FromMilliseconds(100))
            };

            task.ProvideEvents(TestData.Events(new string('a', 40) + "!"));

            Assert.AreEqual(0, task.GetTempBanVictims().Count);
            Assert.IsTrue(logger.Contains("took longer than", SeverityLevel.Warning));
        }

        [TestMethod]
        public void FromConfiguration_RejectsBrokenRules()
        {
            string path = TestData.CopyShippedConfig();
            try
            {
                var logger = new TestLogger();
                var config = new XmlServiceConfiguration(logger, path);
                config.Load();
                IPersistentTaskConfiguration c = config.TaskConfigurations.First();
                c.Regex = "(unclosed";

                Assert.ThrowsExactly<FormatException>(() => GenericIPBlockingTask.FromConfiguration(c, logger));
            }
            finally
            {
                TestData.DeleteFolderOf(path);
            }
        }
    }
}
