using ALGGatekeeper.Config;
using ALGGatekeeper.DTOs;
using ALGGatekeeper.Logging;
using ALGGatekeeper.Tasks;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ALGGatekeeper.Tests
{
    /// <summary>logger that only collects messages</summary>
    internal sealed class TestLogger : ILogger
    {
        public SeverityLevel LogLevel { get; set; } = SeverityLevel.Debug;

        public bool IsEnabled(SeverityLevel severity) => severity != SeverityLevel.Off;

        public List<LogEntry> Entries { get; } = new List<LogEntry>();

        public void Dump(string message, SeverityLevel severity)
        {
            lock (Entries)
                Entries.Add(new LogEntry { Date = DateTime.Now, Message = message, Severity = severity });
        }

        public void Dump(Exception e, SeverityLevel severity = SeverityLevel.Error) => Dump(e.ToString(), severity);

        public void SetConsoleHistoryMaxCount(int count) { }

        public IList<LogEntry> GetConsoleHistory(long afterId = 0) => Entries.ToList();

        public bool Contains(string text, SeverityLevel? severity = null) =>
            Entries.Any(e => e.Message.Contains(text) && (severity == null || e.Severity == severity));
    }

    internal static class TestData
    {
        /// <summary>the default config.xml shipped with the service (copied by the test project)</summary>
        public static string ShippedConfigPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TestData", "config.xml");

        /// <summary>a copy of the shipped config in a temp folder, deleted by the caller</summary>
        public static string CopyShippedConfig()
        {
            string dir = Path.Combine(Path.GetTempPath(), "algtest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, "config.xml");
            File.Copy(ShippedConfigPath, path);
            return path;
        }

        public static void DeleteFolderOf(string path)
        {
            try
            {
                Directory.Delete(Path.GetDirectoryName(path), recursive: true);
            }
            catch
            {
                // temp files, best effort
            }
        }

        /// <summary>loads one rule from the shipped configuration</summary>
        public static GenericIPBlockingTask LoadShippedTask(string name, TestLogger logger = null)
        {
            logger = logger ?? new TestLogger();
            var config = new XmlServiceConfiguration(logger, ShippedConfigPath);
            config.Load();
            IPersistentTaskConfiguration taskConfig = config.TaskConfigurations.Single(t => t.TaskName == name);
            return GenericIPBlockingTask.FromConfiguration(taskConfig, logger);
        }

        /// <summary>
        /// builds an event the way EventRecord.ToXml() renders it (single quotes, no line breaks)
        /// </summary>
        public static string EventXml(int eventId, string provider, params (string Name, string Value)[] data)
        {
            var sb = new StringBuilder();
            sb.Append("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>");
            sb.Append("<Provider Name='").Append(provider).Append("' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>");
            sb.Append("<EventID>").Append(eventId).Append("</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>");
            sb.Append("<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2026-11-13T15:00:00.1234567Z'/>");
            sb.Append("<EventRecordID>4711</EventRecordID><Correlation/><Execution ProcessID='812' ThreadID='4620'/>");
            sb.Append("<Channel>Security</Channel><Computer>SERVER01</Computer><Security/></System><EventData>");
            foreach (var (name, value) in data)
            {
                if (name == null)
                    sb.Append("<Data>").Append(Escape(value)).Append("</Data>");
                else
                    sb.Append("<Data Name='").Append(name).Append("'>").Append(Escape(value)).Append("</Data>");
            }
            sb.Append("</EventData></Event>");
            return sb.ToString();
        }

        /// <summary>Security event 4625 (failed logon)</summary>
        public static string Failed4625(string ip) => EventXml(4625, "Microsoft-Windows-Security-Auditing",
            ("SubjectUserSid", "S-1-0-0"), ("SubjectUserName", "-"), ("TargetUserName", "administrator"),
            ("Status", "0xc000006d"), ("FailureReason", "%%2313"), ("LogonType", "3"), ("LogonProcessName", "NtLmSsp "),
            ("AuthenticationPackageName", "NTLM"), ("WorkstationName", "-"), ("IpAddress", ip), ("IpPort", "0"));

        /// <summary>Security event 4624 (successful logon)</summary>
        public static string Success4624(string ip, int logonType) => EventXml(4624, "Microsoft-Windows-Security-Auditing",
            ("SubjectUserSid", "S-1-5-18"), ("TargetUserSid", "S-1-5-21-1-2-3-500"), ("TargetUserName", "admin"),
            ("TargetLogonId", "0x3e7"), ("LogonType", logonType.ToString()), ("LogonProcessName", "User32 "),
            ("AuthenticationPackageName", "Negotiate"), ("WorkstationName", "SERVER01"), ("ProcessName", "C:\\Windows\\System32\\svchost.exe"),
            ("IpAddress", ip), ("IpPort", "0"));

        /// <summary>escapes like the event log renderer: only &amp;, &lt; and &gt;</summary>
        private static string Escape(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

        public static List<ExtractedEventRecord> Events(params string[] xmls) =>
            xmls.Select((x, i) => new ExtractedEventRecord { Xml = x, TimeCreated = DateTime.UtcNow.AddSeconds(-1), RecordId = i }).ToList();

        public static List<ExtractedEventRecord> Repeat(string xml, int count) =>
            Enumerable.Range(0, count).Select(i => new ExtractedEventRecord { Xml = xml, TimeCreated = DateTime.UtcNow.AddSeconds(-1), RecordId = i }).ToList();
    }
}
