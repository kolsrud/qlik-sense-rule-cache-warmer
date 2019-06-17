using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Qlik.Sense.RestClient;

namespace RuleCacheWarmer
{
    class Flags
    {
        public Uri Uri { get; }
        public int Port { get; }
        public int Threads { get; }
        public string PathToCerts { get; }
        public string PathToUsers { get; }
        public string UserPrincipalNameSuffix { get; }
        public bool ClearCache { get; }

        public Flags(string[] args)
        {
            Uri = new Uri("https://localhost");
            Port = 4242;
            Threads = 2;
            UserPrincipalNameSuffix = null;
            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-u":
                        i++;
                        if (i == args.Length)
                            PrintUsage();
                        try
                        {
                            Uri = new Uri(args[i]);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Unable to parse argument \"{args[i]}\" as uri: {e.Message}");
                            PrintUsage();
                        }
                        break;
                    case "-n":
                        i++;
                        if (i == args.Length)
                            PrintUsage();

                        UserPrincipalNameSuffix = args[i];
                        break;
                    case "-p":
                        i++;
                        if (i == args.Length)
                            PrintUsage();
                        if (!int.TryParse(args[i], out var port))
                        {
                            Console.WriteLine($"Unable to parse port \"{args[i]}\" as int.");
                            PrintUsage();
                        }
                        Port = port;
                        break;
                    case "-t":
                        i++;
                        if (i == args.Length)
                            PrintUsage();
                        if (!int.TryParse(args[i], out var threads))
                        {
                            Console.WriteLine($"Unable to parse threads \"{args[i]}\" as int.");
                            PrintUsage();
                        }
                        Threads = threads;
                        break;
                    case "-c":
                        i++;
                        if (i == args.Length)
                            PrintUsage();
                        if (!Directory.Exists(args[i]))
                        {
                            Console.WriteLine($"Cannot find certificate directory \"{args[i]}\".");
                            PrintUsage();
                        }
                        PathToCerts = args[i];
                        break;
                    case "-d":
                        ClearCache = true;
                        break;
                    default:
                        if (i != args.Length - 1)
                            PrintUsage();
                        if (!File.Exists(args[i]))
                        {
                            Console.WriteLine($"Cannot find user specification file \"{args[i]}\".");
                            PrintUsage();
                        }

                        PathToUsers = args[i];
                        break;
                }
            }

            if (PathToUsers == null)
            {
                Console.WriteLine($"No user specification supplied.");
                PrintUsage();
            }

            PrintConfiguration();
        }

        private void PrintConfiguration()
        {
            Console.WriteLine($"Configuration used: <url>                        - {Uri}");
            Console.WriteLine($"                    <user principle name suffix> - {UserPrincipalNameSuffix ?? "<None>"}");
            Console.WriteLine($"                    <port>                       - {Port}");
            Console.WriteLine($"                    <threads>                    - {Threads}");
            Console.WriteLine($"                    <certs>                      - {PathToCerts ?? "Load certificates from store"}");
        }

        private static void PrintUsage()
        {
            var binName = System.AppDomain.CurrentDomain.FriendlyName;
            Console.WriteLine(@"Usage:    {0} [-u <url>] [-n <user principle name suffix>] [-p <port>] [-t <threads>] [-c <path to certs>] <path to users>", binName);
            Console.WriteLine(@"Defaults: <url>                        - https://localhost");
            Console.WriteLine(@"          <user principle name suffix> - None");
            Console.WriteLine(@"          <port>                       - 4242");
            Console.WriteLine(@"          <threads>                    - 2");
            Console.WriteLine(@"          <certs>                      - load from store instead of file");
            Console.WriteLine(@"Example:  {0} -u https://my.server.url -p 4242 -c C:\Tmp\Certs C:\Tmp\Users.txt", binName);
            Console.WriteLine(@"          {0} C:\Tmp\Users.txt", binName);
            Environment.Exit(1);
        }
    }

    class Program
    {
        const string appTableBody =
            "{\"entity\":\"App\",\"columns\":[{\"name\":\"id\",\"columnType\":\"Property\",\"definition\":\"id\"},{\"name\":\"privileges\",\"columnType\":\"Privileges\",\"definition\":\"privileges\"},{\"name\":\"name\",\"columnType\":\"Property\",\"definition\":\"name\"},{\"name\":\"owner\",\"columnType\":\"Property\",\"definition\":\"owner\"},{\"name\":\"publishTime\",\"columnType\":\"Property\",\"definition\":\"publishTime\"},{\"name\":\"AppStatuss\",\"columnType\":\"List\",\"definition\":\"AppStatus\",\"list\":[{\"name\":\"statusType\",\"columnType\":\"Property\",\"definition\":\"statusType\"},{\"name\":\"statusValue\",\"columnType\":\"Property\",\"definition\":\"statusValue\"},{\"name\":\"id\",\"columnType\":\"Property\",\"definition\":\"id\"}]},{\"name\":\"stream\",\"columnType\":\"Property\",\"definition\":\"stream\"},{\"name\":\"tags\",\"columnType\":\"List\",\"definition\":\"tag\",\"list\":[{\"name\":\"name\",\"columnType\":\"Property\",\"definition\":\"name\"},{\"name\":\"id\",\"columnType\":\"Property\",\"definition\":\"id\"}]}]}";

        static void Main(string[] args)
        {
            var flags = new Flags(args);

            RestClient.MaximumConcurrentCalls = flags.Threads;
            var certs = flags.PathToCerts == null ? RestClient.LoadCertificateFromStore() : RestClient.LoadCertificateFromDirectory(flags.PathToCerts);

            try
            {
                var client = new RestClient(flags.Uri.AbsoluteUri);
                client.AsDirectConnection("INTERNAL", "sa_repository", flags.Port, false, certs);

                Console.WriteLine("Connecting to {0}", client.Url);
                client.Get("/qrs/about");
                var appCnt = client.Get("/qrs/app/count");
                Console.WriteLine("Connection successfully established.");
                Console.WriteLine("Total number of apps: " + appCnt);
                if (flags.ClearCache)
                    Console.WriteLine("Clearing repository rules security rules cache." + client.Post("/qrs/systemrule/security/resetcache", ""));
            }
            catch (Exception e)
            {
                Console.WriteLine("Connection failed with message: " + e.Message + " ");
                throw;
            }

            var users = File.ReadAllLines(flags.PathToUsers).Where(IsOkUser).ToArray();
            foreach (var domainUser in users)
            {
                AddJob(() => ExecQuery(flags, domainUser.Trim(), certs));
            }
            Console.WriteLine($"({_running}, {_notCompleted}, {_completed})\tAll jobs enqueued.");
            var sw = new Stopwatch();
            sw.Reset();
            sw.Start();
            ProcessQueue(flags.Threads);
            sw.Stop();
            Console.WriteLine($"Total time: {sw.Elapsed}");
        }

        private static bool IsOkUser(string domainUser, int lineNr)
        {
            var splitUser = domainUser.Trim().Split('\\');
            if (splitUser.Length != 2)
            {
                Console.WriteLine($"Skipping line {lineNr + 1}: Malformed user '{domainUser}'. Expected format <domain>\\<user>");
                return false;
            }
            if (string.IsNullOrWhiteSpace(splitUser[0]))
            {
                Console.WriteLine($"Skipping line {lineNr + 1}: Malformed user '{domainUser}'. Empty domain.");
                return false;
            }
            if (string.IsNullOrWhiteSpace(splitUser[1]))
            {
                Console.WriteLine($"Skipping line {lineNr + 1}: Malformed user '{domainUser}'. Empty user.");
                return false;
            }

            return true;
        }

        private static int _notCompleted, _running, _completed;

        private static async Task ExecQuery(Flags flags, string domainUser, X509Certificate2Collection certs)
        {
            var domain = domainUser.Split('\\')[0];
            var user = domainUser.Split('\\')[1];
            var newClient = new RestClient(flags.Uri.AbsoluteUri);
            newClient.AsDirectConnection(domain, user, flags.Port, false, certs);
            var securityHeader = "SecureRequest=true; LicenseContext=UserAccess; Context=ManagementAccess;";
            if (flags.UserPrincipalNameSuffix != null)
                securityHeader = $"{securityHeader} UserPrincipleName={user.ToUpper()}{flags.UserPrincipalNameSuffix};";
            newClient.CustomHeaders.Add("X-Qlik-Security", securityHeader);
            var sw = new Stopwatch();
            sw.Reset();
            sw.Start();
            var appCnt = await newClient.GetAsync("/qrs/app/count");
            await newClient.PostAsync("/qrs/App/table?orderAscending=true&skip=0&sortColumn=name&take=200", appTableBody);
            Interlocked.Decrement(ref _notCompleted);
            Interlocked.Increment(ref _completed);
            Console.WriteLine($"({_running}, {_notCompleted}, {_completed})\tCache warmed for user: {domainUser}\tApps: {appCnt}\t({sw.Elapsed})");
            sw.Stop();
        }

        private static void ProcessQueue(int threadCnt)
        {
            var workerThreads = Enumerable.Range(0, threadCnt).Select(_ => Task.Run(WorkerThread)).ToArray();
            _running = threadCnt;
            Console.WriteLine($"({_running}, {_notCompleted}, {_completed})\tWorker threads created.");
            Task.WaitAll(workerThreads);
        }

        private static async Task WorkerThread()
        {
            while (Queue.TryDequeue(out var action))
            {
                await action();
            }
            Interlocked.Decrement(ref _running);
        }


        private static readonly ConcurrentQueue<Func<Task>> Queue = new ConcurrentQueue<Func<Task>>();

        private static void AddJob(Func<Task> action)
        {
            Interlocked.Increment(ref _notCompleted);
            Queue.Enqueue(action);
        }
    }
}
