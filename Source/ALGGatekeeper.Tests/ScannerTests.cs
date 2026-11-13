using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace ALGGatekeeper.Tests
{
    [TestClass]
    public class LogRequestTests
    {
        [TestMethod]
        public void EventIsRelevantWhenAllBoostersOfOneRuleMatch()
        {
            var request = new LogRequest();
            request.AddBoosters(new[] { ">4625</EventID>", "IpAddress" });
            request.AddBoosters(new[] { ">4624</EventID>", "LogonType" });

            Assert.IsTrue(request.IsRelevant(TestData.Failed4625("203.0.113.1")));
            Assert.IsTrue(request.IsRelevant(TestData.Success4624("203.0.113.1", 10)));
            Assert.IsFalse(request.IsRelevant(TestData.EventXml(4634, "Microsoft-Windows-Security-Auditing", ("TargetUserName", "bob"))));
        }

        [TestMethod]
        public void RuleWithoutBoosters_AcceptsEverything()
        {
            var request = new LogRequest();
            request.AddBoosters(new[] { "nothing matches this" });
            request.AddBoosters(new string[0]);

            Assert.IsTrue(request.IsRelevant("<Event/>"));
            Assert.AreEqual("*", request.FilterKey);
        }

        [TestMethod]
        public void FilterKey_DependsOnRulesNotOnOrder()
        {
            var a = new LogRequest();
            a.AddBoosters(new[] { "x", "y" });
            a.AddBoosters(new[] { "z" });

            var b = new LogRequest();
            b.AddBoosters(new[] { "z" });
            b.AddBoosters(new[] { "x", "y" });

            var c = new LogRequest();
            c.AddBoosters(new[] { "x" });

            Assert.AreEqual(a.FilterKey, b.FilterKey);
            Assert.AreNotEqual(a.FilterKey, c.FilterKey);
        }

        [TestMethod]
        public void ShippedSecurityRules_FilterOutOrdinaryEvents()
        {
            var request = new LogRequest();
            foreach (string name in new[] { "TrustRDPLogins", "BlockRDPBrutersBySecurity4625", "BlockVPNBrutersBySecurity6273" })
                request.AddBoosters(TestData.LoadShippedTask(name).Boosters);

            // a logoff, a process creation, a privilege use: very frequent, never needed
            string[] noise =
            {
                TestData.EventXml(4634, "Microsoft-Windows-Security-Auditing", ("TargetUserName", "bob"), ("LogonType", "3")),
                TestData.EventXml(4688, "Microsoft-Windows-Security-Auditing", ("NewProcessName", "C:\\x.exe")),
                TestData.EventXml(4672, "Microsoft-Windows-Security-Auditing", ("SubjectUserName", "SYSTEM"))
            };

            Assert.IsFalse(noise.Any(request.IsRelevant));
        }
    }
}
