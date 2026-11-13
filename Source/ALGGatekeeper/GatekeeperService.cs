using ALGGatekeeper.Config;
using ALGGatekeeper.Contracts;
using ALGGatekeeper.Contracts.DTO;
using ALGGatekeeper.DTOs;
using ALGGatekeeper.Logging;
using ALGGatekeeper.SystemAPI;
using ALGGatekeeper.Tasks;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.ServiceModel;
using System.ServiceProcess;
using System.Threading;

namespace ALGGatekeeper
{
    [ServiceBehavior(ConcurrencyMode = ConcurrencyMode.Single, InstanceContextMode = InstanceContextMode.Single, IncludeExceptionDetailInFaults = false)]
    public class GatekeeperService : ServiceBase, IGatekeeperService
    {
        #region constants

        /// <summary>a task that needs longer than this per cycle gets a performance warning</summary>
        private static readonly TimeSpan SlowTaskThreshold = TimeSpan.FromSeconds(5);

        /// <summary>a missing event log (e.g. OpenSSH not installed) is looked for again after this time</summary>
        private static readonly TimeSpan MissingLogRetry = TimeSpan.FromHours(1);

        /// <summary>upper limit of events read per log and cycle, protects the memory during massive attacks</summary>
        private const int MaxEventsPerLogAndCycle = 50000;

        /// <summary>console lines sent per call (keeps every answer far below the message size limit)</summary>
        private const int MaxConsoleEntriesPerCall = 2000;
        private const int MaxConsoleCharactersPerCall = 2 * 1024 * 1024;

        /// <summary>upper limit of addresses accepted in one management call</summary>
        private const int MaxAddressesPerCall = 100000;

        #endregion

        #region private members

        private readonly FirewallAPI _firewallApi = new FirewallAPI();
        private readonly ILogger _logger;
        private readonly IPersistentServiceConfiguration _serviceconfiguration;
        private readonly string _statePath;

        /// <summary>guards all shared state below and every firewall access</summary>
        private readonly object _syncObject = new object();

        private readonly ManualResetEvent _stopSignal = new ManualResetEvent(false);
        private readonly AutoResetEvent _wakeUpSignal = new AutoResetEvent(false);

        private ServiceHost _serviceHost;
        private readonly object _hostLock = new object();
        private Thread _workerThread;

        /// <summary>all loaded tasks, active or not</summary>
        private readonly List<GenericIPBlockingTask> _logTasks = new List<GenericIPBlockingTask>();
        private readonly Dictionary<GenericIPBlockingTask, DateTime> _perfWarningIssued = new Dictionary<GenericIPBlockingTask, DateTime>();

        private List<IPAddress> _lastPolledTempBans = new List<IPAddress>();
        private HashSet<IPAddress> _trustedIPs = new HashSet<IPAddress>();
        private HashSet<IPAddress> _lastBannedIPs = new HashSet<IPAddress>();

        private IReadOnlyList<string> _whitelistSource;
        private List<IPPattern> _whitelist = new List<IPPattern>();

        private long _savedStateVersion = -1;

        /// <summary>what was pushed to the firewall last time, to skip unchanged pushes</summary>
        private string _pushedSignature;
        private DateTime _pushedAt = DateTime.MinValue;
        private string _lastVerifiedSignature;

        /// <summary>even without changes the firewall rules are checked (and repaired) this often</summary>
        private static readonly TimeSpan FirewallVerifyInterval = TimeSpan.FromMinutes(5);

        #endregion

        #region public constructor

        internal GatekeeperService(ILogger logger, IPersistentServiceConfiguration configuration, string statePath = null)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _serviceconfiguration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _statePath = statePath ?? TaskStateStore.DefaultPath;

            ServiceName = ProductInfo.ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        #endregion

        #region public properties

        public static string Version =>
            typeof(GatekeeperService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(GatekeeperService).Assembly.GetName().Version.ToString();

        #endregion

        #region WCF operations

        public GlobalConfigDTO GetGlobalConfig()
        {
            return Execute(() =>
            {
                lock (_syncObject)
                {
                    return new GlobalConfigDTO()
                    {
                        ConsoleBackLog = _serviceconfiguration.ConsoleBackLog,
                        EventLogInterval = _serviceconfiguration.EventLogInterval,
                        MonitorOnly = _serviceconfiguration.MonitorOnly,
                        LogLevel = (SeverityLevelDTO)(int)_serviceconfiguration.LogLevel,
                        GenericTaskConfigurations = _logTasks.Select(ipt => new GenericIPBlockingTaskDTO()
                        {
                            Active = ipt.Active,
                            IsTrustRule = ipt.IsTrustTask,
                            Description = ipt.Description,
                            EventAge = ipt.EventAge,
                            EventPath = ipt.EventPath.ToList(),
                            LockTime = ipt.LockTime,
                            OnlyNewEvents = ipt.OnlyNew,
                            PermaBanCount = ipt.PermaBanCount,
                            Regex = ipt.Regex.ToString(),
                            RegexBoosters = ipt.Boosters.ToList(),
                            TaskName = ipt.Name,
                            TriggerCount = ipt.TriggerCount
                        }).ToList()
                    };
                }
            });
        }

        public bool GetIsRunning()
        {
            return Execute(() => true);
        }

        public string GetServiceVersion()
        {
            return Execute(() => Version);
        }

        public string[] GetPermanentlyBannedIPs()
        {
            return Execute(() => _serviceconfiguration.BlacklistAddresses.Select(ip => ip.ToString()).ToArray());
        }

        public string[] GetWhiteListEntries()
        {
            return Execute(() => _serviceconfiguration.WhitelistPatterns.ToArray());
        }

        public string[] GetTemporarilyBannedIPs()
        {
            return Execute(() =>
            {
                lock (_syncObject)
                {
                    var permanent = new HashSet<IPAddress>(_serviceconfiguration.BlacklistAddresses);
                    return _lastPolledTempBans.Where(p => !permanent.Contains(p) && !IsProtected(p)).Select(p => p.ToString()).ToArray();
                }
            });
        }

        public string[] GetTrustedIPs()
        {
            return Execute(() =>
            {
                lock (_syncObject)
                    return _trustedIPs.OrderBy(ip => ip, IPAddressTools.Comparer).Select(ip => ip.ToString()).ToArray();
            });
        }

        public void SetPermanentBan(IPAddress address)
        {
            SetPermanentBans(new[] { address });
        }

        public void SetPermanentBans(IPAddress[] addressList)
        {
            Execute(() =>
            {
                if (addressList == null || addressList.Length == 0)
                    throw new ArgumentException("No address was given.");
                if (addressList.Length > MaxAddressesPerCall)
                    throw new ArgumentException($"At most {MaxAddressesPerCall} addresses can be added at once.");

                lock (_syncObject)
                {
                    int added = _serviceconfiguration.AddBlackListAddresses(addressList);
                    _logger.Dump($"{added} address(es) were added to the permanent ban list by an administrator.", SeverityLevel.Info);
                    PushBanList();
                }
            });
        }

        public void ClearPermanentBan(IPAddress address)
        {
            Execute(() =>
            {
                RequireAddress(address);
                lock (_syncObject)
                {
                    if (_serviceconfiguration.RemoveBlackListAddress(address))
                        _logger.Dump($"{address} was removed from the permanent ban list by an administrator.", SeverityLevel.Info);
                    PushBanList();
                }
            });
        }

        public void AddWhiteListEntry(string filter)
        {
            Execute(() =>
            {
                lock (_syncObject)
                {
                    if (_serviceconfiguration.AddWhiteListPattern(filter))
                        _logger.Dump($"'{filter.Trim()}' was added to the white list by an administrator.", SeverityLevel.Info);
                    PushBanList();
                }
            });
        }

        public void RemoveWhiteListEntry(string filter)
        {
            Execute(() =>
            {
                lock (_syncObject)
                {
                    if (_serviceconfiguration.RemoveWhiteListPattern(filter))
                        _logger.Dump($"'{filter}' was removed from the white list by an administrator.", SeverityLevel.Info);
                    PushBanList();
                }
            });
        }

        public IList<LogEntryDTO> GetConsoleHistory(long afterId)
        {
            // limited by count and by size: the console catches up over a few refreshes
            return Execute(() =>
            {
                var result = new List<LogEntryDTO>();
                long characters = 0;
                foreach (LogEntry entry in _logger.GetConsoleHistory(afterId))
                {
                    characters += entry.Message?.Length ?? 0;
                    if (result.Count >= MaxConsoleEntriesPerCall || (result.Count > 0 && characters > MaxConsoleCharactersPerCall))
                        break;

                    result.Add(new LogEntryDTO
                    {
                        Id = entry.Id,
                        Date = entry.Date,
                        Message = entry.Message,
                        Severity = (SeverityLevelDTO)(int)entry.Severity
                    });
                }
                return (IList<LogEntryDTO>)result;
            });
        }

        public void SaveGlobalConfig(SeverityLevelDTO logLevel, int consoleBackLog, int checkInterval, bool monitorOnly)
        {
            Execute(() =>
            {
                if (!Enum.IsDefined(typeof(SeverityLevelDTO), logLevel))
                    throw new ArgumentException($"Unknown log level {logLevel}.");
                if (consoleBackLog < SettingsLimits.MinConsoleBacklog || consoleBackLog > SettingsLimits.MaxConsoleBacklog)
                    throw new ArgumentException($"The console backlog must be between {SettingsLimits.MinConsoleBacklog} and {SettingsLimits.MaxConsoleBacklog}.");
                if (checkInterval < SettingsLimits.MinCheckInterval || checkInterval > SettingsLimits.MaxCheckInterval)
                    throw new ArgumentException($"The check interval must be between {SettingsLimits.MinCheckInterval} and {SettingsLimits.MaxCheckInterval} seconds.");

                lock (_syncObject)
                {
                    bool monitorChanged = _serviceconfiguration.MonitorOnly != monitorOnly;

                    _serviceconfiguration.LogLevel = (SeverityLevel)(int)logLevel;
                    _serviceconfiguration.ConsoleBackLog = consoleBackLog;
                    _serviceconfiguration.EventLogInterval = checkInterval;
                    _serviceconfiguration.MonitorOnly = monitorOnly;

                    _logger.Dump($"Global settings changed by an administrator (log level {logLevel}, backlog {consoleBackLog}, interval {checkInterval}s, simulation mode {(monitorOnly ? "ON" : "off")}).", SeverityLevel.Warning);

                    if (monitorChanged)
                        PushBanList();
                }

                _wakeUpSignal.Set();
            });
        }

        public void SaveTaskSettings(string taskName, bool active, int lockTime, int eventAge, int triggerCount, int permaBanCount)
        {
            Execute(() =>
            {
                if (string.IsNullOrWhiteSpace(taskName))
                    throw new ArgumentException("No rule name was given.");

                string error = SettingsLimits.ValidateTaskSettings(lockTime, eventAge, triggerCount, permaBanCount);
                if (error != null)
                    throw new ArgumentException(error);

                if (permaBanCount < 0)
                    permaBanCount = -1;

                lock (_syncObject)
                {
                    IPersistentTaskConfiguration config = _serviceconfiguration.TaskConfigurations
                        .FirstOrDefault(c => string.Equals(c.TaskName, taskName.Trim(), StringComparison.OrdinalIgnoreCase));

                    if (config == null)
                        throw new ArgumentException($"There is no rule named '{taskName}'.");

                    config.Active = active;
                    config.LockTime = lockTime;
                    config.EventAge = eventAge;
                    config.TriggerCount = triggerCount;
                    config.PermaBanCount = permaBanCount;

                    GenericIPBlockingTask running = _logTasks.FirstOrDefault(t => string.Equals(t.Name, config.TaskName, StringComparison.OrdinalIgnoreCase));
                    running?.ApplySettings(active, lockTime, eventAge, triggerCount, permaBanCount);

                    _logger.Dump($"Rule {config.TaskName} changed by an administrator: active={active}, ban/trust time={lockTime}s, time frame={eventAge}s, attempts={triggerCount}, permanent after={permaBanCount}.", SeverityLevel.Warning);
                }

                _wakeUpSignal.Set();
            });
        }

        public void RemoveTemporaryBan(IPAddress address)
        {
            Execute(() =>
            {
                RequireAddress(address);
                address = IPAddressTools.Normalize(address);

                lock (_syncObject)
                {
                    _logger.Dump($"Removing IP {address} from temporary ban list", SeverityLevel.Info);
                    foreach (var task in _logTasks.Where(t => !t.IsTrustTask))
                        task.Forget(address);

                    _lastPolledTempBans.Remove(address);
                    PushBanList();
                }
            });
        }

        public void RemoveTrust(IPAddress address)
        {
            Execute(() =>
            {
                RequireAddress(address);
                address = IPAddressTools.Normalize(address);

                lock (_syncObject)
                {
                    _logger.Dump($"An administrator revoked the trust of {address}", SeverityLevel.Info);
                    foreach (var task in _logTasks.Where(t => t.IsTrustTask))
                        task.Forget(address);

                    _trustedIPs.Remove(address);
                    PushBanList();
                }
            });
        }

        #endregion

        #region service lifecycle

        protected override void OnStart(string[] args)
        {
            StartWorking();
        }

        protected override void OnStop()
        {
            RequestAdditionalTime(30000);
            StopWorking();
        }

        protected override void OnShutdown()
        {
            StopWorking();
        }

        /// <summary>
        /// starts the management endpoint and the worker thread (also used by the /console mode)
        /// </summary>
        internal void StartWorking()
        {
            _stopSignal.Reset();

            // the management endpoint is opened by the worker once the configuration is loaded,
            // so a console call can never work on an empty configuration
            _workerThread = new Thread(Run)
            {
                IsBackground = true,
                Name = "ALG Gatekeeper worker"
            };
            _workerThread.Start();
        }

        /// <summary>
        /// stops everything; the worker saves the state and removes the firewall rules on its way out
        /// </summary>
        internal void StopWorking()
        {
            _stopSignal.Set();

            CloseServiceHost();

            if (_workerThread != null && !_workerThread.Join(TimeSpan.FromSeconds(25)))
                _logger.Dump("Service could not terminate normally.", SeverityLevel.Warning);
            else
                _logger.Dump("Service terminated OK", SeverityLevel.Info);
        }

        private void OpenServiceHost()
        {
            lock (_hostLock)
            {
                if (_stopSignal.WaitOne(0) || _serviceHost != null)
                    return;

                try
                {
                    var host = new ServiceHost(this, new Uri(ProductInfo.PipeBaseAddress));
                    host.AddServiceEndpoint(typeof(IGatekeeperService), ProductInfo.CreateBinding(), ProductInfo.PipeEndpointName);
                    host.Open();
                    _serviceHost = host;
                }
                catch (Exception ex)
                {
                    // the protection keeps running, only the console can not connect
                    _logger.Dump($"The management endpoint could not be opened, the console will not be able to connect: {ex.Message}", SeverityLevel.Error);
                }
            }
        }

        private void CloseServiceHost()
        {
            ServiceHost host;
            lock (_hostLock)
            {
                host = _serviceHost;
                _serviceHost = null;
            }
            if (host == null)
                return;

            try
            {
                host.Close(TimeSpan.FromSeconds(5));
            }
            catch
            {
                host.Abort();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                CloseServiceHost();
                _firewallApi.Dispose();
                _stopSignal.Dispose();
                _wakeUpSignal.Dispose();
            }

            base.Dispose(disposing);
        }

        #endregion

        #region private operations: management

        /// <summary>
        /// runs a management operation: checks the caller and turns errors into faults the console can show
        /// </summary>
        private T Execute<T>(Func<T> operation)
        {
            EnsureClientPrivileges();

            try
            {
                return operation();
            }
            catch (FaultException)
            {
                throw;
            }
            catch (ArgumentException ex)
            {
                throw new FaultException<ServiceFaultDTO>(new ServiceFaultDTO(ServiceErorCode.invalidArgument, ex.Message), ex.Message);
            }
            catch (Exception ex)
            {
                _logger.Dump(ex, SeverityLevel.Error);
                string message = $"The service could not complete the operation: {ex.Message}";
                throw new FaultException<ServiceFaultDTO>(new ServiceFaultDTO(ServiceErorCode.internalError, message), message);
            }
        }

        private void Execute(Action operation)
        {
            Execute(() =>
            {
                operation();
                return true;
            });
        }

        private static void RequireAddress(IPAddress address)
        {
            if (address == null)
                throw new ArgumentException("No address was given.");
        }

        /// <summary>
        /// ensures the caller is an elevated member of the local Administrators group
        /// </summary>
        private void EnsureClientPrivileges()
        {
            WindowsIdentity identity = ServiceSecurityContext.Current?.WindowsIdentity;

            bool isAdmin = identity != null
                && identity.IsAuthenticated
                && !identity.IsAnonymous
                && !identity.IsGuest
                && new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

            if (isAdmin)
                return;

            string who = identity?.Name ?? "<unknown>";
            _logger.Dump($"There was an attempt to access the management interface without authorization. ({who})", SeverityLevel.Warning);
            throw new FaultException<ServiceFaultDTO>(
                new ServiceFaultDTO(
                    ServiceErorCode.clientNotAdministrator,
                    $"Your account {who} is not an Administrator! Please run this software with Administrator privileges. The client will exit...",
                    true), "access denied");
        }

        #endregion

        #region private operations: banning

        /// <summary>
        /// true if the address must never be banned (white list or trusted after a successful login)
        /// </summary>
        private bool IsProtected(IPAddress address)
        {
            if (_trustedIPs.Contains(address))
                return true;

            List<IPPattern> patterns = GetWhitelist();
            for (int i = 0; i < patterns.Count; i++)
            {
                if (patterns[i].IsMatch(address))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// the parsed white list; re-parsed only when the configuration hands out a new list
        /// </summary>
        private List<IPPattern> GetWhitelist()
        {
            IReadOnlyList<string> current = _serviceconfiguration.WhitelistPatterns;
            if (!ReferenceEquals(current, _whitelistSource))
            {
                _whitelist = current.Select(IPPattern.ParseLenient).ToList();
                _whitelistSource = current;
            }

            return _whitelist;
        }

        /// <summary>
        /// Pushes the current ban list down into the firewall. Must be called inside lock(_syncObject).
        /// </summary>
        private void PushBanList()
        {
            List<IPAddress> banList = _lastPolledTempBans
                .Concat(_serviceconfiguration.BlacklistAddresses)
                .Select(IPAddressTools.Normalize)
                .Where(IPAddressTools.IsBannable)
                .Distinct()
                .Where(address => !IsProtected(address))
                .ToList();

            bool simulation = _serviceconfiguration.MonitorOnly;
            string prefix = simulation ? "[SIMULATION, not banned] " : string.Empty;

            // in simulation mode the firewall rules are kept empty (and therefore disabled)
            List<IPAddress> toFirewall = simulation ? new List<IPAddress>() : banList;
            toFirewall.Sort(IPAddressTools.Comparer);
            string signature = string.Join(",", toFirewall);

            if (signature != _pushedSignature || DateTime.UtcNow - _pushedAt > FirewallVerifyInterval)
            {
                // reset first: if the firewall call fails, the next call must try again
                _pushedSignature = null;
                if (_firewallApi.AdjustIPBanList(toFirewall) && signature == _lastVerifiedSignature)
                    _logger.Dump("The firewall rules were checked and brought back in line with the ban list.", SeverityLevel.Verbose);

                _pushedSignature = signature;
                _lastVerifiedSignature = signature;
                _pushedAt = DateTime.UtcNow;
            }

            var newSet = new HashSet<IPAddress>(banList);

            foreach (IPAddress ip in _lastBannedIPs.Where(ip => !newSet.Contains(ip)))
                _logger.Dump($"{prefix}Removed {ip} from the ban list", SeverityLevel.Info);

            foreach (IPAddress ip in banList.Where(ip => !_lastBannedIPs.Contains(ip)))
                _logger.Dump($"{prefix}Banned {ip}", SeverityLevel.Info);

            _lastBannedIPs = newSet;
            _logger.Dump($"{prefix}Pushed {banList.Count} IPs down to the firewall for banning.", SeverityLevel.Debug);
        }

        #endregion

        #region private operations: worker

        /// <summary>
        /// creates the tasks from configuration (inactive ones too, so they can be switched on at runtime)
        /// </summary>
        private void InitWorkersFromConfig()
        {
            lock (_syncObject)
            {
                _logTasks.Clear();

                foreach (var config in _serviceconfiguration.TaskConfigurations)
                {
                    try
                    {
                        _logTasks.Add(GenericIPBlockingTask.FromConfiguration(config, _logger));
                        _logger.Dump($"Loaded rule {config.TaskName} ({(config.Active ? "active" : "inactive")}, {config.Kind})", SeverityLevel.Verbose);
                    }
                    catch (Exception ex)
                    {
                        // one bad rule must not stop the protection by the others
                        _logger.Dump($"Rule {config.TaskName} could not be loaded and is skipped: {ex.Message}", SeverityLevel.Error);
                    }
                }

                Dictionary<string, TaskState> states = TaskStateStore.Load(_statePath, _logger);
                foreach (GenericIPBlockingTask task in _logTasks)
                {
                    if (states.TryGetValue(task.Name, out TaskState state))
                        task.ImportState(state);
                }

                if (states.Count > 0)
                    _logger.Dump("Restored the bans and trusted IPs saved before the last stop.", SeverityLevel.Info);
            }
        }

        private void SaveStateIfChanged()
        {
            try
            {
                System.Xml.Linq.XDocument doc;
                long version;
                lock (_syncObject)
                {
                    version = _logTasks.Sum(t => t.StateVersion);
                    if (version == _savedStateVersion)
                        return;

                    doc = TaskStateStore.ToXml(_logTasks.Select(t => t.ExportState()));
                }

                TaskStateStore.Save(_statePath, doc);
                _savedStateVersion = version;
            }
            catch (Exception ex)
            {
                _logger.Dump($"The ban state could not be saved: {ex.Message}", SeverityLevel.Warning);
            }
        }

        /// <summary>
        /// the worker loop
        /// </summary>
        private void Run()
        {
            try
            {
                try
                {
                    //reload configuration in case of external changes
                    _serviceconfiguration.Load();
                }
                catch (Exception ex)
                {
                    _logger.Dump($"config.xml could not be loaded, the service can not work: {ex.Message}", SeverityLevel.Critical);
                    ThreadPool.QueueUserWorkItem(_ => Stop());
                    return;
                }

                InitWorkersFromConfig();
                OpenServiceHost();

                if (_serviceconfiguration.MonitorOnly)
                    _logger.Dump("SIMULATION MODE is on: the firewall is not changed, bans are only logged.", SeverityLevel.Warning);

                // re-apply the permanent bans and the restored temporary bans right away
                lock (_syncObject)
                {
                    _lastPolledTempBans = PollTasks(out _trustedIPs, out _);
                    TryPushBanList();
                }

                var scanner = new EventScanner(_logger, DateTime.UtcNow, MaxEventsPerLogAndCycle, MissingLogRetry);

                do
                {
                    try
                    {
                        RunCycle(scanner);
                    }
                    catch (Exception executionException)
                    {
                        _logger.Dump(executionException, SeverityLevel.Error);
                    }

                    SaveStateIfChanged();
                }
                while (WaitForNextCycle());
            }
            catch (Exception e)
            {
                _logger.Dump(e, SeverityLevel.Critical);
                ThreadPool.QueueUserWorkItem(_ => Stop());
            }
            finally
            {
                SaveStateIfChanged();
                lock (_syncObject)
                {
                    try
                    {
                        _firewallApi.ClearIPBanList();
                    }
                    catch (Exception ex)
                    {
                        _logger.Dump(ex, SeverityLevel.Warning);
                    }
                }
            }
        }

        /// <summary>
        /// waits for the check interval; returns false when the service is stopping
        /// </summary>
        private bool WaitForNextCycle()
        {
            int seconds = Math.Max(SettingsLimits.MinCheckInterval, _serviceconfiguration.EventLogInterval);
            int signaled = WaitHandle.WaitAny(new WaitHandle[] { _stopSignal, _wakeUpSignal }, TimeSpan.FromSeconds(seconds));
            return signaled != 0;
        }

        private void TryPushBanList()
        {
            try
            {
                PushBanList();
            }
            catch (Exception ex)
            {
                _logger.Dump(ex, SeverityLevel.Error);
            }
        }

        private void RunCycle(EventScanner scanner)
        {
            DateTime cycleStart = DateTime.UtcNow;
            _logger.Dump("Scanning the logs now.", SeverityLevel.Debug);

            List<GenericIPBlockingTask> activeTasks;
            lock (_syncObject)
                activeTasks = _logTasks.Where(t => t.Active).ToList();

            // which logs are needed, and how far back
            var logs = new Dictionary<string, LogRequest>(StringComparer.OrdinalIgnoreCase);
            foreach (GenericIPBlockingTask task in activeTasks)
            {
                foreach (string path in task.EventPath)
                {
                    if (!logs.TryGetValue(path, out LogRequest request))
                        logs[path] = request = new LogRequest();

                    if (!task.OnlyNew)
                        request.MaxAgeSeconds = Math.Max(request.MaxAgeSeconds, task.EventAge);

                    request.AddBoosters(task.Boosters);
                }
            }

            var results = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var log in logs)
            {
                ScanResult result = scanner.Scan(log.Key, log.Value, cycleStart);
                if (result != null)
                    results[log.Key] = result;
            }

            _logger.Dump($"Scanning finished in {(DateTime.UtcNow - cycleStart).TotalMilliseconds:0}[ms]", SeverityLevel.Debug);

            // hand the events to the tasks: one call per task, events of all its logs together
            foreach (GenericIPBlockingTask task in activeTasks)
            {
                var events = new List<ExtractedEventRecord>();
                DateTime minTime = cycleStart.AddSeconds(-task.EventAge);

                foreach (string path in task.EventPath)
                {
                    if (!results.TryGetValue(path, out ScanResult result))
                        continue;

                    if (task.OnlyNew)
                        events.AddRange(result.NewEvents);
                    else
                        events.AddRange(result.TimeFramedEvents.Where(e => e.TimeCreated > minTime));
                }

                if (events.Count == 0)
                    continue;

                _logger.Dump($"Provided {events.Count} events for {task.Name}", SeverityLevel.Verbose);

                var watch = Stopwatch.StartNew();
                task.ProvideEvents(events);
                watch.Stop();

                if (watch.Elapsed > SlowTaskThreshold)
                {
                    lock (_syncObject)
                    {
                        if (!_perfWarningIssued.TryGetValue(task, out DateTime last) || DateTime.UtcNow > last.AddHours(24))
                        {
                            _logger.Dump($"Warning: Rule {task.Name} needed {watch.Elapsed.TotalSeconds:0.0}s. Maybe there are very many events (problems in domain configuration, stale hidden credentials..), or the regex is slow. This can cause CPU spikes. Try better boosters, or try to find the root problem.", SeverityLevel.Warning);
                            _perfWarningIssued[task] = DateTime.UtcNow;
                        }
                    }
                }
            }

            lock (_syncObject)
            {
                List<IPAddress> tempBans = PollTasks(out HashSet<IPAddress> trusted, out List<IPAddress> permaBans);
                _trustedIPs = trusted;

                List<IPAddress> newPermaBans = permaBans.Where(p => !IsProtected(p)).ToList();
                if (newPermaBans.Count > 0)
                {
                    if (_serviceconfiguration.MonitorOnly)
                    {
                        foreach (IPAddress ip in newPermaBans)
                            _logger.Dump($"[SIMULATION, not banned] {ip} would have been banned permanently.", SeverityLevel.Info);
                    }
                    else
                    {
                        try
                        {
                            // the bans are active in memory even if config.xml can not be written right now
                            _serviceconfiguration.AddBlackListAddresses(newPermaBans);
                        }
                        catch (Exception ex)
                        {
                            _logger.Dump($"The permanent bans could not be saved to config.xml (they are active anyway and are saved with the next change): {ex.Message}", SeverityLevel.Error);
                        }
                    }
                }

                _lastPolledTempBans = tempBans;
                PushBanList();
            }

            _logger.Dump($"-----Cycle complete, sleeping {_serviceconfiguration.EventLogInterval} s......", SeverityLevel.Debug);
        }

        /// <summary>
        /// asks the active tasks for the IPs to ban / trust. Must be called inside lock(_syncObject).
        /// </summary>
        private List<IPAddress> PollTasks(out HashSet<IPAddress> trusted, out List<IPAddress> permaBans)
        {
            var tempBans = new HashSet<IPAddress>();
            var perma = new HashSet<IPAddress>();
            trusted = new HashSet<IPAddress>();

            foreach (GenericIPBlockingTask task in _logTasks)
            {
                // always called, also for inactive tasks, so that expired entries are cleaned up
                List<IPAddress> temp = task.GetTempBanVictims();
                List<IPAddress> permanent = task.GetPermaBanVictims();

                if (!task.Active)
                    continue;

                if (task.IsTrustTask)
                {
                    trusted.UnionWith(temp);
                    continue;
                }

                tempBans.UnionWith(temp);
                perma.UnionWith(permanent);

                if (temp.Count > 0 || permanent.Count > 0)
                    _logger.Dump($"Polled {task.Name} and got {temp.Count} temporary and {permanent.Count} permanent ban(s)", SeverityLevel.Verbose);
            }

            permaBans = perma.ToList();
            return tempBans.ToList();
        }

        #endregion
    }
}
