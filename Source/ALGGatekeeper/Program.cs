using ALGGatekeeper.Config;
using ALGGatekeeper.Contracts;
using ALGGatekeeper.Logging;
using ALGGatekeeper.SystemAPI;
using ALGGatekeeper.Tasks;
using System;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;

namespace ALGGatekeeper
{
    /// <summary>
    /// Entry point. Without arguments the program runs as Windows service.
    /// Command line options exist for the installer, for troubleshooting and for emergencies.
    /// </summary>
    public static class Program
    {
        private const int ExitOk = 0;
        private const int ExitError = 1;
        private const int ExitUsage = 2;

        public static int Main(string[] args)
        {
            args = args ?? new string[0];

            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try
                {
                    new DefaultLogger().Dump($"Unexpected error, the service stops (Windows restarts it automatically): {e.ExceptionObject}", SeverityLevel.Critical);
                }
                catch
                {
                    // nothing left to do
                }
            };

            if (args.Length == 0)
            {
                if (!Environment.UserInteractive)
                {
                    ServiceBase.Run(CreateService());
                    return ExitOk;
                }

                PrintHelp();
                return ExitUsage;
            }

            string command = args[0].TrimStart('/', '-').ToLowerInvariant();

            try
            {
                switch (command)
                {
                    case "console":
                        return RunInConsole();

                    case "migrateconfig":
                        return MigrateConfig(args);

                    case "validateconfig":
                        return ValidateConfig(args.Length > 1 ? args[1] : XmlConfigFile.DefaultPath);

                    case "removefirewallrules":
                        return RemoveFirewallRules(args.Skip(1).Any(a => a.TrimStart('/', '-').Equals("legacy", StringComparison.OrdinalIgnoreCase)));

                    case "version":
                        Console.WriteLine($"{ProductInfo.DisplayName} {GatekeeperService.Version}");
                        return ExitOk;

                    case "help":
                    case "?":
                    case "h":
                        PrintHelp();
                        return ExitOk;

                    default:
                        Console.Error.WriteLine($"Unknown option: {args[0]}");
                        PrintHelp();
                        return ExitUsage;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return ExitError;
            }
        }

        private static GatekeeperService CreateService()
        {
            ILogger logger = new DefaultLogger();
            IPersistentServiceConfiguration serviceConfiguration = new XmlServiceConfiguration(logger);
            return new GatekeeperService(logger, serviceConfiguration);
        }

        private static void PrintHelp()
        {
            Console.WriteLine($@"{ProductInfo.DisplayName} {GatekeeperService.Version}
Bans brute force attackers found in the Windows event log, using the Windows Firewall.

Without options the program runs as the Windows service ""{ProductInfo.ServiceName}"" (installed by the setup).

Options (run as Administrator):
  /console                     run in this window instead of as a service (stop the service first)
  /validateconfig [file]       check config.xml (or the given file) and list problems
  /migrateconfig <old> [new]   copy your settings from an old config.xml into the new one
                               (new defaults to config.xml next to this program)
  /removefirewallrules         remove all ""{ProductInfo.FirewallRuleName}"" firewall rules
  /removefirewallrules /legacy remove the rules of the old EvlWatcher program
  /version                     show the version

Locked out? From another connection (VM console, KVM, other IP) run:
  sc stop {ProductInfo.ServiceName}
Stopping the service removes all its firewall rules immediately.");
        }

        private static int RunInConsole()
        {
            using (GatekeeperService service = CreateService())
            using (var exit = new ManualResetEvent(false))
            {
                Console.CancelKeyPress += (s, e) =>
                {
                    e.Cancel = true;
                    exit.Set();
                };

                service.StartWorking();
                Console.WriteLine("Running. Press Ctrl+C to stop.");
                exit.WaitOne();
                service.StopWorking();
            }

            return ExitOk;
        }

        private static int MigrateConfig(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("Usage: /migrateconfig <old config.xml> [new config.xml]");
                return ExitUsage;
            }

            string oldPath = Path.GetFullPath(args[1]);
            string newPath = Path.GetFullPath(args.Length > 2 ? args[2] : XmlConfigFile.DefaultPath);

            if (!File.Exists(oldPath))
            {
                Console.Error.WriteLine($"Not found: {oldPath}");
                return ExitError;
            }

            if (!File.Exists(newPath))
            {
                Console.Error.WriteLine($"Not found: {newPath}");
                return ExitError;
            }

            if (string.Equals(oldPath, newPath, StringComparison.OrdinalIgnoreCase))
            {
                Console.Error.WriteLine("The old and the new configuration are the same file.");
                return ExitUsage;
            }

            Console.WriteLine(ConfigMigrator.Migrate(oldPath, newPath));
            Console.WriteLine($"Settings migrated from {oldPath} into {newPath}.");

            // the result must still be a valid configuration
            return ValidateConfig(newPath);
        }

        private static int ValidateConfig(string path)
        {
            var logger = new ConsoleOnlyLogger();
            var config = new XmlServiceConfiguration(logger, Path.GetFullPath(path));
            config.Load();

            int ok = 0;
            foreach (IPersistentTaskConfiguration task in config.TaskConfigurations)
            {
                try
                {
                    GenericIPBlockingTask.FromConfiguration(task, logger);
                    ok++;
                }
                catch (Exception ex)
                {
                    logger.Dump($"Rule {task.TaskName}: {ex.Message}", SeverityLevel.Error);
                }
            }

            Console.WriteLine($"{ok} rule(s) OK, {logger.Problems} problem(s) found in {path}.");
            return logger.Problems == 0 ? ExitOk : ExitError;
        }

        private static int RemoveFirewallRules(bool legacy)
        {
            string name = legacy ? ProductInfo.LegacyName : ProductInfo.FirewallRuleName;
            using (var api = new FirewallAPI(name))
                api.ClearIPBanList();

            Console.WriteLine($"Removed the \"{name}\" firewall rules.");
            return ExitOk;
        }

        /// <summary>
        /// logger for the command line tools: prints warnings and errors, counts them
        /// </summary>
        private sealed class ConsoleOnlyLogger : ILogger
        {
            public SeverityLevel LogLevel { get; set; } = SeverityLevel.Warning;

            public bool IsEnabled(SeverityLevel severity) => severity >= SeverityLevel.Warning && severity != SeverityLevel.Off;

            public int Problems { get; private set; }

            /// <summary>only errors count as problems; warnings (e.g. a value that was corrected) are just shown</summary>
            public void Dump(string message, SeverityLevel severity)
            {
                if (severity < SeverityLevel.Warning)
                    return;

                if (severity >= SeverityLevel.Error)
                    Problems++;

                Console.WriteLine($"[{severity}] {message}");
            }

            public void Dump(Exception e, SeverityLevel severity = SeverityLevel.Error) => Dump(e?.Message, severity);

            public void SetConsoleHistoryMaxCount(int count) { }

            public System.Collections.Generic.IList<LogEntry> GetConsoleHistory(long afterId = 0) => new System.Collections.Generic.List<LogEntry>();
        }
    }
}
