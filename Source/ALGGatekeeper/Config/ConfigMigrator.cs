using ALGGatekeeper.Contracts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Xml.Linq;

namespace ALGGatekeeper.Config
{
    /// <summary>
    /// Carries the user's settings from an old config.xml (of ALG Gatekeeper or of EvlWatcher, same format)
    /// into the new default config.xml that comes with an update.
    ///
    /// Rules:
    /// <list type="bullet">
    /// <item>&lt;Global&gt;: everything is taken from the old file. White list and ban list are merged (nothing is lost).</item>
    /// <item>Tasks that exist in both files: the new definition (regex, boosters, event path) is used,
    ///   but the user's Active flag and tuning values (LockTime, EventAge, TriggerCount, PermaBanCount, OnlyNew) are kept.</item>
    /// <item>Tasks that only exist in the old file (the user's own rules) are appended.</item>
    /// </list>
    /// </summary>
    internal static class ConfigMigrator
    {
        private static readonly string[] TunableTaskElements = { "LockTime", "EventAge", "TriggerCount", "PermaBanCount", "OnlyNew" };
        private static readonly string[] ListSettings = { "WhiteList", "Banlist" };

        /// <summary>
        /// Merges <paramref name="oldConfigPath"/> into <paramref name="newConfigPath"/> and saves the result to <paramref name="newConfigPath"/>.
        /// </summary>
        /// <returns>a human readable summary</returns>
        public static string Migrate(string oldConfigPath, string newConfigPath)
        {
            XDocument oldDoc = XmlConfigFile.Load(oldConfigPath);
            XDocument newDoc = XmlConfigFile.Load(newConfigPath);

            string summary = Merge(oldDoc, newDoc);

            XmlConfigFile.Save(newDoc, newConfigPath);
            return summary;
        }

        /// <summary>
        /// merges the user settings of <paramref name="oldDoc"/> into <paramref name="newDoc"/> (in memory)
        /// </summary>
        public static string Merge(XDocument oldDoc, XDocument newDoc)
        {
            if (oldDoc?.Root == null)
                throw new FormatException("The old configuration has no root element.");
            if (newDoc?.Root == null)
                throw new FormatException("The new configuration has no root element.");

            var report = new List<string>();

            MergeGlobal(oldDoc.Root.Element("Global"), newDoc.Root, report);
            MergeTasks(oldDoc, newDoc, report);

            return string.Join(Environment.NewLine, report);
        }

        private static void MergeGlobal(XElement oldGlobal, XElement newRoot, List<string> report)
        {
            if (oldGlobal == null)
            {
                report.Add("The old configuration has no <Global> section, global settings were not migrated.");
                return;
            }

            XElement newGlobal = newRoot.Element("Global");
            if (newGlobal == null)
            {
                newGlobal = new XElement("Global");
                newRoot.AddFirst(newGlobal);
            }

            foreach (XElement oldSetting in oldGlobal.Elements())
            {
                string name = oldSetting.Name.LocalName;
                XElement newSetting = newGlobal.Element(name);

                if (ListSettings.Contains(name))
                {
                    string merged = MergeLists(newSetting?.Value, oldSetting.Value, name == "Banlist");
                    if (newSetting == null)
                        newGlobal.Add(newSetting = new XElement(name));
                    newSetting.Value = merged;
                    report.Add($"{name}: merged ({CountEntries(merged)} entries).");
                    continue;
                }

                if (newSetting == null)
                {
                    newGlobal.Add(new XElement(oldSetting));
                }
                else
                {
                    newSetting.Value = oldSetting.Value.Trim();
                }
                report.Add($"{name}: kept your value '{oldSetting.Value.Trim()}'.");
            }
        }

        private static string MergeLists(string newValue, string oldValue, bool isIpList)
        {
            var result = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string raw in (oldValue ?? string.Empty).Split(';').Concat((newValue ?? string.Empty).Split(';')))
            {
                string entry = raw.Trim();
                if (entry.Length == 0)
                    continue;

                if (isIpList)
                {
                    // normalize, so 1.2.3.4 and ::ffff:1.2.3.4 are not stored twice; invalid entries are dropped
                    if (!IPAddressTools.TryParseStrict(entry, out IPAddress ip))
                        continue;
                    entry = ip.ToString();
                }

                if (seen.Add(entry))
                    result.Add(entry);
            }

            return result.Count == 0 ? string.Empty : string.Join(";", result) + ";";
        }

        private static int CountEntries(string list)
        {
            return (list ?? string.Empty).Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Length;
        }

        private static void MergeTasks(XDocument oldDoc, XDocument newDoc, List<string> report)
        {
            XElement newTasks = newDoc.Root.Element("Tasks");
            if (newTasks == null)
            {
                newTasks = new XElement("Tasks");
                newDoc.Root.Add(newTasks);
            }

            var newByName = new Dictionary<string, XElement>(StringComparer.OrdinalIgnoreCase);
            foreach (XElement t in newDoc.Descendants("Task"))
            {
                string n = (string)t.Attribute("Name");
                if (!string.IsNullOrWhiteSpace(n) && !newByName.ContainsKey(n.Trim()))
                    newByName.Add(n.Trim(), t);
            }

            var handled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (XElement oldTask in oldDoc.Descendants("Task"))
            {
                string name = ((string)oldTask.Attribute("Name"))?.Trim();
                if (string.IsNullOrEmpty(name) || !handled.Add(name))
                    continue;

                if (newByName.TryGetValue(name, out XElement newTask))
                {
                    XAttribute oldActive = oldTask.Attribute("Active");
                    if (oldActive != null)
                        newTask.SetAttributeValue("Active", oldActive.Value.Trim());

                    foreach (string element in TunableTaskElements)
                    {
                        XElement oldEl = oldTask.Element(element);
                        XElement newEl = newTask.Element(element);
                        if (oldEl == null)
                            continue;

                        if (newEl == null)
                            newTask.Add(new XElement(element, oldEl.Value.Trim()));
                        else
                            newEl.Value = oldEl.Value.Trim();
                    }

                    report.Add($"Task {name}: updated to the new definition, your settings (active, times, counts) were kept.");
                }
                else
                {
                    newTasks.Add(new XElement(oldTask));
                    report.Add($"Task {name}: your own task was carried over.");
                }
            }
        }
    }
}
