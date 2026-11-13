using System;

namespace ALGGatekeeper.DTOs
{
    public class ExtractedEventRecord
    {
        public DateTime TimeCreated { get; internal set; }
        public string Xml { get; internal set; }

        /// <summary>
        /// the record id of the event inside its log (used to avoid rendering the same event to XML again and again)
        /// </summary>
        public long? RecordId { get; internal set; }
    }
}
