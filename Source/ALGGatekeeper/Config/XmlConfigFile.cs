using System;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace ALGGatekeeper.Config
{
    /// <summary>
    /// Loads and saves config.xml in a safe way.
    /// </summary>
    internal static class XmlConfigFile
    {
        /// <summary>
        /// the file name of the configuration
        /// </summary>
        public const string FileName = "config.xml";

        /// <summary>
        /// config.xml next to the executable
        /// </summary>
        public static string DefaultPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, FileName);

        /// <summary>
        /// Loads an XML file. DTDs and external entities are never processed.
        /// </summary>
        public static XDocument Load(string path)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };

            using (var reader = XmlReader.Create(path, settings))
            {
                return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
            }
        }

        /// <summary>
        /// Saves atomically: the document is written to a temporary file first and then swapped in,
        /// so a crash or power loss while saving can never leave a half written (corrupt) configuration behind.
        /// </summary>
        public static void Save(XDocument document, string path)
        {
            string fullPath = Path.GetFullPath(path);
            string tempPath = fullPath + ".tmp";

            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true),
                Indent = false // whitespace is preserved from loading, so the user's formatting and comments stay as they are
            };

            using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var writer = XmlWriter.Create(stream, settings))
            {
                document.Save(writer);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            if (File.Exists(fullPath))
                File.Replace(tempPath, fullPath, destinationBackupFileName: null, ignoreMetadataErrors: true);
            else
                File.Move(tempPath, fullPath);
        }

        /// <summary>
        /// load - change - save in one step (the caller is responsible for locking)
        /// </summary>
        public static void Update(string path, Action<XDocument> change)
        {
            XDocument d = Load(path);
            if (d.Root == null)
                throw new FormatException($"{path} has no root element.");

            change(d);
            Save(d, path);
        }

        /// <summary>
        /// the &lt;Task&gt; element with the given name
        /// </summary>
        public static XElement FindTask(XDocument document, string taskName)
        {
            foreach (XElement task in document.Descendants("Task"))
            {
                if (string.Equals(((string)task.Attribute("Name"))?.Trim(), taskName, StringComparison.Ordinal))
                    return task;
            }

            throw new FormatException($"No configuration node for task {taskName}");
        }

        /// <summary>
        /// returns the child element, creating it when missing
        /// </summary>
        public static XElement GetOrAdd(XElement parent, string name, bool addFirst = false)
        {
            XElement element = parent.Element(name);
            if (element == null)
            {
                element = new XElement(name);
                if (addFirst)
                    parent.AddFirst(element);
                else
                    parent.Add(element);
            }
            return element;
        }

        /// <summary>
        /// reads the trimmed value of a child element, or null if it does not exist
        /// </summary>
        public static string GetValue(XElement parent, string name)
        {
            return parent?.Element(name)?.Value?.Trim();
        }
    }
}
