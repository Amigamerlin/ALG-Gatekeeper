using ALGGatekeeper.Contracts;
using ALGGatekeeper.Contracts.DTO;
using ALGGatekeeperConsole.Model;
using ALGGatekeeperConsole.MVVMBase;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Reflection;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;

namespace ALGGatekeeperConsole.ViewModel
{
    public class MainWindowViewModel : GuiObject, IDisposable
    {
        #region private members

        private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(2);

        private readonly GatekeeperModel _model = new GatekeeperModel();
        private readonly DispatcherTimer _timer;
        private bool _refreshing;
        private bool _disposed;

        private bool _isServiceResponding;
        private bool _isMonitorOnly;
        private string _serviceVersion = "";
        private string _permaBanIPString = "";
        private string _whiteListFilter = "";
        private string _consoleText = "";
        private readonly List<LogEntryDTO> _consoleEntries = new List<LogEntryDTO>();
        private long _lastConsoleId;
        private SeverityLevelDTO _selectedConsoleLevel = SeverityLevelDTO.Info;

        private bool _isInGlobalEditMode;
        private SeverityLevelDTO _loglevel;
        private int _consoleBackLog;
        private int _checkInterval;
        private bool _monitorOnlySetting;

        private RuleItem _selectedRule;
        private RuleItem _selectedTestRule;
        private string _currentTestRegex;
        private string _xmltext;

        #endregion

        #region public .ctor

        public MainWindowViewModel()
        {
            TemporarilyBannedIPs.CollectionChanged += (s, e) => Notify(nameof(CanAddTemporaryToPerma));

            // the designer creates the view model too; it must not try to connect there
            if (System.ComponentModel.DesignerProperties.GetIsInDesignMode(new DependencyObject()))
                return;

            _timer = new DispatcherTimer { Interval = RefreshInterval };
            _timer.Tick += (s, e) => Refresh();
            _timer.Start();
            Refresh();
        }

        #endregion

        #region refresh (background)

        /// <summary>
        /// everything that is fetched from the service in one refresh
        /// </summary>
        private sealed class Snapshot
        {
            public bool Responding;
            public string Version;
            public GlobalConfigDTO Global;
            public IPAddress[] Temporary;
            public IPAddress[] Permanent;
            public IPAddress[] Trusted;
            public string[] WhiteList;
            public IList<LogEntryDTO> Console;
            public FaultException<ServiceFaultDTO> Fault;
        }

        private void Refresh()
        {
            if (_refreshing || _disposed)
                return;

            _refreshing = true;

            bool ipTab = IsIPTabSelected;
            bool consoleTab = IsConsoleTabSelected;
            bool needVersion = string.IsNullOrEmpty(_serviceVersion);
            long afterId = _lastConsoleId;

            Task.Run(() =>
            {
                var s = new Snapshot();
                try
                {
                    s.Global = _model.GetGlobalConfig();
                    s.Responding = true;

                    if (needVersion)
                        s.Version = _model.GetServiceVersion();

                    if (ipTab)
                    {
                        s.Temporary = _model.GetTemporarilyBannedIPs();
                        s.Permanent = _model.GetPermanentlyBannedIPs();
                        s.Trusted = _model.GetTrustedIPs();
                        s.WhiteList = _model.GetWhiteListPatterns();
                    }

                    if (consoleTab)
                        s.Console = _model.GetConsoleHistory(afterId);
                }
                catch (FaultException<ServiceFaultDTO> fault)
                {
                    s.Fault = fault;
                    s.Responding = false;
                }
                catch (Exception)
                {
                    // service not installed, stopped or starting: shown in the status bar
                    s.Responding = false;
                }
                return s;
            }).ContinueWith(t =>
            {
                _refreshing = false;
                if (!_disposed && t.Status == TaskStatus.RanToCompletion)
                    Apply(t.Result);
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }

        private void Apply(Snapshot s)
        {
            if (s.Fault != null && s.Fault.Detail != null && s.Fault.Detail.Code == ServiceErorCode.clientNotAdministrator)
            {
                _timer?.Stop();
                MessageBox.Show(s.Fault.Detail.Message, ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Error);
                Application.Current.Shutdown();
                return;
            }

            IsServiceResponding = s.Responding;
            if (!s.Responding)
            {
                _consoleEntries.Clear();
                _lastConsoleId = 0;
                return;
            }

            if (s.Version != null)
            {
                _serviceVersion = s.Version;
                Notify(nameof(StatusText));
            }

            if (s.Global != null)
            {
                IsMonitorOnly = s.Global.MonitorOnly;

                if (!IsInGlobalEditMode)
                {
                    LogLevel = s.Global.LogLevel;
                    CheckInterval = s.Global.EventLogInterval;
                    ConsoleBackLog = s.Global.ConsoleBackLog;
                    MonitorOnlySetting = s.Global.MonitorOnly;
                }

                UpdateRules(s.Global.GenericTaskConfigurations);
            }

            if (s.Temporary != null) Sync(TemporarilyBannedIPs, s.Temporary);
            if (s.Permanent != null) Sync(PermanentlyBannedIPs, s.Permanent);
            if (s.Trusted != null) Sync(TrustedIPs, s.Trusted);
            if (s.WhiteList != null) Sync(WhiteListedPatterns, s.WhiteList);
            if (s.Console != null) UpdateConsole(s.Console, s.Global?.ConsoleBackLog ?? SettingsLimits.DefaultConsoleBacklog);
        }

        /// <summary>
        /// makes the collection equal to the source with as few changes as possible (keeps the selection)
        /// </summary>
        private static void Sync<T>(ObservableCollection<T> target, IList<T> source)
        {
            var wanted = new HashSet<T>(source);
            for (int i = target.Count - 1; i >= 0; i--)
            {
                if (!wanted.Contains(target[i]))
                    target.RemoveAt(i);
            }

            var present = new HashSet<T>(target);
            foreach (T item in source)
            {
                if (present.Add(item))
                    target.Add(item);
            }
        }

        /// <summary>
        /// appends the new entries (only new ones are fetched) and rebuilds the text when something changed
        /// </summary>
        private void UpdateConsole(IList<LogEntryDTO> newEntries, int backlog)
        {
            if (newEntries.Count == 0 && _consoleText.Length > 0)
                return;

            _consoleEntries.AddRange(newEntries);
            if (newEntries.Count > 0)
                _lastConsoleId = newEntries[newEntries.Count - 1].Id;

            int excess = _consoleEntries.Count - Math.Max(0, backlog);
            if (excess > 0)
                _consoleEntries.RemoveRange(0, excess);

            RebuildConsoleText();
        }

        private void RebuildConsoleText()
        {
            SeverityLevelDTO level = SelectedConsoleLevel;
            var sb = new StringBuilder();

            if (level != SeverityLevelDTO.Off)
            {
                foreach (var log in _consoleEntries)
                {
                    if (log.Severity >= level)
                        sb.Append(log.Date.ToString("yyyy-MM-dd HH:mm:ss")).Append(" [").Append(log.Severity).Append("] ").AppendLine(log.Message);
                }
            }

            ConsoleText = sb.ToString();
        }

        private void UpdateRules(IList<GenericIPBlockingTaskDTO> tasks)
        {
            if (tasks == null)
                return;

            // never overwrite what the user is editing
            if (Rules.Any(r => r.IsDirty))
                return;

            string selected = SelectedRule?.Name;
            string selectedTest = SelectedTestRule?.Name;

            bool same = Rules.Count == tasks.Count && Rules.Zip(tasks, (r, t) =>
                r.Name == t.TaskName && r.Active == t.Active && r.LockTime == t.LockTime && r.EventAge == t.EventAge &&
                r.TriggerCount == t.TriggerCount && r.PermaBanCount == (t.PermaBanCount < 0 ? -1 : t.PermaBanCount)).All(x => x);

            if (same)
                return;

            Rules.Clear();
            foreach (var t in tasks)
                Rules.Add(new RuleItem(t));

            SelectedRule = Rules.FirstOrDefault(r => r.Name == selected) ?? Rules.FirstOrDefault();
            _selectedTestRule = Rules.FirstOrDefault(r => r.Name == selectedTest);
            Notify(nameof(SelectedTestRule));
        }

        #endregion

        #region commands

        /// <summary>
        /// runs an action against the service and shows errors to the user
        /// </summary>
        private void Run(Action action, string successMessage = null)
        {
            try
            {
                action();
                if (successMessage != null)
                    MessageBox.Show(successMessage, ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (FaultException<ServiceFaultDTO> fault)
            {
                MessageBox.Show(fault.Detail?.Message ?? fault.Message, ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex) when (ex is CommunicationException || ex is TimeoutException)
            {
                MessageBox.Show($"The {ProductInfo.DisplayName} service can not be reached. Is it running?\n\n{ex.Message}", ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Error);
            }

            Refresh();
        }

        private bool Confirm(string question)
        {
            return MessageBox.Show(question, ProductInfo.DisplayName, MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;
        }

        public ICommand RemoveTemporaryBanCommand => new RelayCommand(
            p => Run(() => _model.RemoveTemporaryBan(SelectedTemporaryIP)),
            p => SelectedTemporaryIP != null && IsServiceResponding);

        public ICommand MoveTemporaryToPermaCommand => new RelayCommand(
            p => Run(() => _model.AddPermanentIPBan(SelectedTemporaryIP)),
            p => SelectedTemporaryIP != null && IsServiceResponding);

        public ICommand MoveAllTemporaryToPermaCommand => new RelayCommand(
            p => { if (Confirm($"Ban all {TemporarilyBannedIPs.Count} temporarily banned IPs permanently?")) Run(() => _model.AddPermanentIPBans(TemporarilyBannedIPs.ToArray())); },
            p => CanAddTemporaryToPerma);

        public ICommand MoveTemporaryToWhiteListCommand => new RelayCommand(
            p => Run(() => _model.AddWhiteListEntry(SelectedTemporaryIP.ToString())),
            p => SelectedTemporaryIP != null && IsServiceResponding);

        public ICommand AddPermaBanCommand => new RelayCommand(
            p => Run(() =>
            {
                if (!IPAddressTools.TryParseStrict(PermaBanIPString, out IPAddress ip))
                    throw new FaultException<ServiceFaultDTO>(new ServiceFaultDTO(ServiceErorCode.invalidArgument, $"'{PermaBanIPString}' is not a valid IP address."));
                _model.AddPermanentIPBan(ip);
                PermaBanIPString = "";
            }),
            p => IsServiceResponding && IPAddressTools.TryParseStrict(PermaBanIPString, out _));

        public ICommand RemovePermaBanCommand => new RelayCommand(
            p => Run(() => _model.RemovePermanentIPBan(SelectedPermanentIP)),
            p => SelectedPermanentIP != null && IsServiceResponding);

        public ICommand AddWhiteListFilterCommand => new RelayCommand(
            p => Run(() =>
            {
                if (!IPPattern.TryParse(WhiteListFilter, out _, out string error))
                    throw new FaultException<ServiceFaultDTO>(new ServiceFaultDTO(ServiceErorCode.invalidArgument, error));
                _model.AddWhiteListEntry(WhiteListFilter.Trim());
                WhiteListFilter = "";
            }),
            p => IsServiceResponding && !string.IsNullOrWhiteSpace(WhiteListFilter));

        public ICommand RemoveWhiteListFilterCommand => new RelayCommand(
            p => Run(() => _model.RemoveWhiteListEntry(SelectedWhiteListPattern)),
            p => SelectedWhiteListPattern != null && IsServiceResponding);

        public ICommand RemoveTrustCommand => new RelayCommand(
            p => Run(() => _model.RemoveTrust(SelectedTrustedIP)),
            p => SelectedTrustedIP != null && IsServiceResponding);

        public ICommand ToggleGlobalConfigEditModeCommand => new RelayCommand(
            p => IsInGlobalEditMode = true,
            p => !IsInGlobalEditMode && IsServiceResponding);

        public ICommand CancelGlobalEditingCommand => new RelayCommand(
            p => { IsInGlobalEditMode = false; Refresh(); },
            p => IsInGlobalEditMode);

        public ICommand SaveGlobalConfigCommand => new RelayCommand(
            p =>
            {
                if (MonitorOnlySetting && !IsMonitorOnly && !Confirm("Turn ON the simulation mode?\n\nNobody will be banned anymore (current bans are lifted), bans are only written to the log."))
                    return;

                Run(() =>
                {
                    _model.SaveGlobalConfig(LogLevel, ConsoleBackLog, CheckInterval, MonitorOnlySetting);
                    IsInGlobalEditMode = false;
                });
            },
            p => IsInGlobalEditMode && IsServiceResponding);

        public ICommand SaveRuleCommand => new RelayCommand(
            p =>
            {
                RuleItem rule = SelectedRule;
                string error = SettingsLimits.ValidateTaskSettings(rule.LockTime, rule.EventAge, rule.TriggerCount, rule.PermaBanCount);
                if (error != null)
                {
                    MessageBox.Show(error, ProductInfo.DisplayName, MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (rule.IsTrustRule && !rule.Active && !Confirm($"Switch off '{rule.Name}'?\n\nThis rule protects you from banning yourself: IPs that logged in successfully are never banned while it is on."))
                    return;

                Run(() =>
                {
                    _model.SaveTaskSettings(rule.Name, rule.Active, rule.LockTime, rule.EventAge, rule.TriggerCount, rule.PermaBanCount);
                    rule.IsDirty = false;
                }, $"The settings of '{rule.Name}' were saved and are active now.");
            },
            p => SelectedRule != null && SelectedRule.IsDirty && IsServiceResponding);

        public ICommand DiscardRuleCommand => new RelayCommand(
            p =>
            {
                foreach (var r in Rules)
                    r.IsDirty = false;
                Rules.Clear();
                Refresh();
            },
            p => Rules.Any(r => r.IsDirty));

        public ICommand TestRegexCommand => new RelayCommand(p => TestRegex(), p => !string.IsNullOrEmpty(CurrentTestRegex));

        public ICommand ResetRegexCommand => new RelayCommand(p => CurrentTestRegex = SelectedTestRule?.Regex, p => SelectedTestRule != null);

        private void TestRegex()
        {
            try
            {
                var regex = new Regex(CurrentTestRegex, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2));
                if (IPAddressTools.TryExtract(regex, XMLText ?? string.Empty, out IPAddress ipAddress))
                    MessageBox.Show($"We could extract the IP {ipAddress} from that.", "Success", MessageBoxButton.OK, MessageBoxImage.None);
                else
                    MessageBox.Show("We couldn't extract an IP from that.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (RegexMatchTimeoutException)
            {
                MessageBox.Show("The regex took too long (more than 2 seconds). The service would skip this event. Please simplify the regex.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (ArgumentException ex)
            {
                MessageBox.Show($"The regex is not valid: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region public properties

        public string WindowTitle => $"{ProductInfo.DisplayName} {Assembly.GetExecutingAssembly().GetName().Version.ToString(3)} - Console";

        public string StatusText => IsServiceResponding
            ? $"Service {ProductInfo.ServiceName} {_serviceVersion} is running."
            : $"Service {ProductInfo.ServiceName} is not responding (not installed, stopped or starting).";

        public IReadOnlyList<SeverityLevelDTO> AvailableLogLevels => _model.ConsoleLevels;

        public bool IsIPTabSelected { get; set; }
        public bool IsConsoleTabSelected { get; set; }

        public bool IsServiceResponding
        {
            get => _isServiceResponding;
            private set
            {
                if (_isServiceResponding == value)
                    return;
                _isServiceResponding = value;
                Notify(nameof(IsServiceResponding));
                Notify(nameof(CanAddTemporaryToPerma));
                Notify(nameof(StatusText));
                if (!value)
                {
                    _serviceVersion = "";
                    IsMonitorOnly = false;
                }
            }
        }

        /// <summary>simulation mode currently active in the service (shown as a warning)</summary>
        public bool IsMonitorOnly
        {
            get => _isMonitorOnly;
            private set { if (_isMonitorOnly != value) { _isMonitorOnly = value; Notify(nameof(IsMonitorOnly)); } }
        }

        public bool CanAddTemporaryToPerma => IsServiceResponding && TemporarilyBannedIPs.Count > 0;

        public ObservableCollection<IPAddress> TemporarilyBannedIPs { get; } = new ObservableCollection<IPAddress>();
        public ObservableCollection<IPAddress> PermanentlyBannedIPs { get; } = new ObservableCollection<IPAddress>();
        public ObservableCollection<IPAddress> TrustedIPs { get; } = new ObservableCollection<IPAddress>();
        public ObservableCollection<string> WhiteListedPatterns { get; } = new ObservableCollection<string>();
        public ObservableCollection<RuleItem> Rules { get; } = new ObservableCollection<RuleItem>();

        public IPAddress SelectedTemporaryIP { get; set; }
        public IPAddress SelectedPermanentIP { get; set; }
        public IPAddress SelectedTrustedIP { get; set; }
        public string SelectedWhiteListPattern { get; set; }

        public string PermaBanIPString
        {
            get => _permaBanIPString;
            set { _permaBanIPString = value; Notify(nameof(PermaBanIPString)); }
        }

        public string WhiteListFilter
        {
            get => _whiteListFilter;
            set { _whiteListFilter = value; Notify(nameof(WhiteListFilter)); }
        }

        public string ConsoleText
        {
            get => _consoleText;
            private set { _consoleText = value; Notify(nameof(ConsoleText)); }
        }

        public SeverityLevelDTO SelectedConsoleLevel
        {
            get => _selectedConsoleLevel;
            set { _selectedConsoleLevel = value; Notify(nameof(SelectedConsoleLevel)); RebuildConsoleText(); }
        }

        public bool IsInGlobalEditMode
        {
            get => _isInGlobalEditMode;
            set { _isInGlobalEditMode = value; Notify(nameof(IsInGlobalEditMode)); }
        }

        public SeverityLevelDTO LogLevel
        {
            get => _loglevel;
            set { _loglevel = value; Notify(nameof(LogLevel)); }
        }

        public int CheckInterval
        {
            get => _checkInterval;
            set { _checkInterval = value; Notify(nameof(CheckInterval)); }
        }

        public int ConsoleBackLog
        {
            get => _consoleBackLog;
            set { _consoleBackLog = value; Notify(nameof(ConsoleBackLog)); }
        }

        /// <summary>the simulation checkbox in the global settings (edited value)</summary>
        public bool MonitorOnlySetting
        {
            get => _monitorOnlySetting;
            set { _monitorOnlySetting = value; Notify(nameof(MonitorOnlySetting)); }
        }

        public RuleItem SelectedRule
        {
            get => _selectedRule;
            set { _selectedRule = value; Notify(nameof(SelectedRule)); }
        }

        public RuleItem SelectedTestRule
        {
            get => _selectedTestRule;
            set
            {
                _selectedTestRule = value;
                Notify(nameof(SelectedTestRule));
                CurrentTestRegex = value?.Regex;
            }
        }

        public string CurrentTestRegex
        {
            get => _currentTestRegex;
            set { _currentTestRegex = value; Notify(nameof(CurrentTestRegex)); }
        }

        public string XMLText
        {
            get => _xmltext;
            set { _xmltext = value; Notify(nameof(XMLText)); }
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _timer?.Stop();
            _model.Dispose();
        }

        #endregion
    }
}
