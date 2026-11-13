using ALGGatekeeper.Contracts.DTO;
using ALGGatekeeperConsole.MVVMBase;
using System;

namespace ALGGatekeeperConsole.ViewModel
{
    /// <summary>
    /// one rule in the "Rules" tab, with editable settings
    /// </summary>
    public class RuleItem : GuiObject
    {
        private bool _active;
        private int _lockTime;
        private int _eventAge;
        private int _triggerCount;
        private int _permaBanCount;
        private bool _isDirty;

        public RuleItem(GenericIPBlockingTaskDTO dto)
        {
            if (dto == null)
                throw new ArgumentNullException(nameof(dto));

            Name = dto.TaskName;
            Description = (dto.Description ?? string.Empty).Trim();
            IsTrustRule = dto.IsTrustRule;
            EventPath = dto.EventPath == null ? string.Empty : string.Join(", ", dto.EventPath);
            Regex = dto.Regex;
            Boosters = dto.RegexBoosters == null ? string.Empty : string.Join(", ", dto.RegexBoosters);

            _active = dto.Active;
            _lockTime = dto.LockTime;
            _eventAge = dto.EventAge;
            _triggerCount = dto.TriggerCount;
            _permaBanCount = dto.PermaBanCount < 0 ? -1 : dto.PermaBanCount;
        }

        public string Name { get; }
        public string Description { get; }
        public bool IsTrustRule { get; }
        public string EventPath { get; }
        public string Regex { get; }
        public string Boosters { get; }

        public string KindText => IsTrustRule ? "Trust (successful logins: never banned)" : "Ban (failed logins)";

        public string DisplayName => (Active ? "" : "(off) ") + Name + (IsTrustRule ? "  [trust]" : "");

        public bool IsDirty
        {
            get => _isDirty;
            set { _isDirty = value; Notify(nameof(IsDirty)); }
        }

        public bool Active
        {
            get => _active;
            set { _active = value; Changed(nameof(Active)); Notify(nameof(DisplayName)); }
        }

        /// <summary>ban duration (or trust duration for trust rules) in seconds</summary>
        public int LockTime
        {
            get => _lockTime;
            set { _lockTime = value; Changed(nameof(LockTime)); Notify(nameof(LockTimeText)); }
        }

        /// <summary>observed time frame in seconds</summary>
        public int EventAge
        {
            get => _eventAge;
            set { _eventAge = value; Changed(nameof(EventAge)); Notify(nameof(EventAgeText)); }
        }

        public int TriggerCount
        {
            get => _triggerCount;
            set { _triggerCount = value; Changed(nameof(TriggerCount)); }
        }

        /// <summary>temporary bans before a permanent ban, -1 = never</summary>
        public int PermaBanCount
        {
            get => _permaBanCount;
            set { _permaBanCount = value; Changed(nameof(PermaBanCount)); Notify(nameof(PermaBanText)); }
        }

        public string LockTimeText => "= " + FormatDuration(LockTime);
        public string EventAgeText => "= " + FormatDuration(EventAge);
        public string PermaBanText => PermaBanCount < 0 ? "never permanent" : PermaBanCount == 0 ? "permanent at the first ban" : $"permanent after {PermaBanCount} temporary bans";

        public static string FormatDuration(int seconds)
        {
            if (seconds <= 0)
                return "-";

            var t = TimeSpan.FromSeconds(seconds);
            if (t.TotalDays >= 1)
                return $"{t.TotalDays:0.##} days";
            if (t.TotalHours >= 1)
                return $"{t.TotalHours:0.##} hours";
            if (t.TotalMinutes >= 1)
                return $"{t.TotalMinutes:0.##} minutes";
            return $"{seconds} seconds";
        }

        private void Changed(string property)
        {
            Notify(property);
            IsDirty = true;
        }

        public override string ToString() => Name;
    }
}
