using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

// ============================================================================
// DirNetBlock —— 目录级内核封网工具
// 选择任意目录，将该目录下所有 .exe 加入 Windows 防火墙（内核 WFP/BFE 执行）
// Block 规则（出站+入站各一条），实现"内核级禁止联网"。
//
// 两种执行方式（同一份源码）：
//   GUI 版（winexe）：双击运行，图形界面选择目录
//   CLI 版（exe）：  命令行 DirNetBlock_cli.exe --block <目录> 等
//
// 加固功能：
//   1. 封禁系统网络工具（curl/certutil/bitsadmin 等，防目录程序"借刀"联网）
//   2. 子进程自动封禁（监控目标目录程序拉起的子进程，拉起即封）
// 封禁前自动确保 Windows 防火墙开启（无条件 set on + 复查 + 重试）。
// ============================================================================
namespace DirNetBlock
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                if (args[0] == "--autostart")
                {
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm(true));
                    return;
                }
                Environment.ExitCode = Cli.Run(args);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(false));
        }
    }

    // ============================ 防火墙封装 ============================
    public static class Firewall
    {
        public const string PREFIX = "DirNetBlock_";

        // 可被"借刀"联网的系统网络工具（默认封禁清单，不含 powershell 以免影响系统管理）
        public static readonly string[] SystemToolNames = {
            "curl.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "wscript.exe", "cscript.exe",
            "ftp.exe", "telnet.exe", "nslookup.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe",
            "net.exe", "net1.exe", "msiexec.exe", "hh.exe", "odbcconf.exe"
        };

        private static readonly Guid FwPolicy2Clsid = new Guid("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD");
        private static readonly Guid FwRuleClsid   = new Guid("2C5BC43E-3369-4C33-AB0C-BE9469677AF4");

        private const int ACTION_BLOCK = 0;
        private const int DIR_IN = 1;
        private const int DIR_OUT = 2;

        public static bool IsAdmin()
        {
            try
            {
                var p = new System.Security.Principal.WindowsPrincipal(
                    System.Security.Principal.WindowsIdentity.GetCurrent());
                return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        // netsh 输出编码：有控制台(CLI)=GBK，无控制台(GUI/winexe)=UTF8。读原始字节自动探测。
        private static string DecodeNetsh(byte[] raw)
        {
            try { return new UTF8Encoding(false, true).GetString(raw); }
            catch { return Encoding.GetEncoding(936).GetString(raw); }
        }

        private static byte[] ReadAllBytes(System.IO.Stream s)
        {
            using (var ms = new System.IO.MemoryStream())
            {
                byte[] buf = new byte[65536];
                int n;
                while ((n = s.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
                return ms.ToArray();
            }
        }

        private static string RunNetshCapture(string args)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi =
                    new System.Diagnostics.ProcessStartInfo("netsh.exe", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
                {
                    byte[] raw = ReadAllBytes(p.StandardOutput.BaseStream);
                    p.WaitForExit();
                    return DecodeNetsh(raw);
                }
            }
            catch { return ""; }
        }

        private static bool RunNetsh(string args)
        {
            try
            {
                System.Diagnostics.ProcessStartInfo psi =
                    new System.Diagnostics.ProcessStartInfo("netsh.exe", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
                {
                    p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return p.ExitCode == 0;
                }
            }
            catch { return false; }
        }

        // 确保 Windows 防火墙开启：无条件 set on + 复查 + 重试
        public static bool EnsureFirewallOn()
        {
            try
            {
                RunNetsh("advfirewall set allprofiles state on");
                if (!IsFirewallOn())
                {
                    RunNetsh("advfirewall set allprofiles state on");
                    Thread.Sleep(500);
                }
                return IsFirewallOn();
            }
            catch { return false; }
        }

        private static bool IsFirewallOn()
        {
            string st = RunNetshCapture("advfirewall show allprofiles state");
            if (string.IsNullOrEmpty(st)) return false;
            bool anyOff = st.IndexOf("OFF", StringComparison.OrdinalIgnoreCase) >= 0
                       || st.IndexOf("关闭", StringComparison.OrdinalIgnoreCase) >= 0;
            return !anyOff;
        }

        private static dynamic NewPolicy() { return Activator.CreateInstance(Type.GetTypeFromCLSID(FwPolicy2Clsid)); }

        public static List<string> EnumerateExes(string dir)
        {
            List<string> result = new List<string>();
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories))
                    result.Add(f);
            }
            catch { }
            return result;
        }

        public static string RuleName(string tag, string exePath)
        {
            string fname = Path.GetFileName(exePath);
            string hash = "";
            using (System.Security.Cryptography.SHA1 sha = System.Security.Cryptography.SHA1.Create())
            {
                byte[] b = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(exePath.ToLowerInvariant()));
                hash = BitConverter.ToString(b, 0, 4).Replace("-", "");
            }
            return PREFIX + tag + "_" + fname + "_" + hash;
        }

        private static int AddOne(dynamic policy, string ruleName, string exePath, int dir, string tag)
        {
            try
            {
                dynamic rule = Activator.CreateInstance(Type.GetTypeFromCLSID(FwRuleClsid));
                rule.Name = ruleName;
                rule.Description = "DirNetBlock kernel-level block rule (" + tag + ")";
                rule.ApplicationName = exePath;
                rule.Enabled = true;
                rule.Direction = dir;
                rule.Action = ACTION_BLOCK;
                rule.InterfaceTypes = "All";
                policy.Rules.Add(rule);
                Marshal.FinalReleaseComObject(rule);
                return 1;
            }
            catch { return 0; }
        }

        // 批量添加（智能路由）：全 ASCII -> netsh 批量脚本；含中文 -> COM
        public static int BlockAll(List<string> exes, Action<string> progress = null)
        {
            return BlockAllTag(exes, "", progress);
        }

        // tag="" 时出站用 OC、入站用 IA；tag 非空（如 ST）时两条都用该 tag
        private static int BlockAllTag(List<string> exes, string tag, Action<string> progress)
        {
            if (exes.Count == 0) return 0;
            bool allAscii = true;
            foreach (string e in exes)
            {
                foreach (char c in e)
                    if (c > 127) { allAscii = false; break; }
                if (!allAscii) break;
            }
            if (allAscii) return BlockAllNetsh(exes, tag);
            return BlockAllCom(exes, tag, progress);
        }

        private static int BlockAllNetsh(List<string> exes, string tag)
        {
            HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var r in ListRules()) existing.Add(r.Item1); } catch { }
            string scriptPath = Path.Combine(Path.GetTempPath(), "DirNetBlock_add_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                StringBuilder sb = new StringBuilder();
                int count = 0;
                foreach (string exe in exes)
                {
                    foreach (var item in new[] { new { d = "out" }, new { d = "in" } })
                    {
                        string t = (tag.Length > 0) ? tag : (item.d == "out" ? "OC" : "IA");
                        string name = RuleName(t, exe);
                        // ST 标签出/入站同名会重复创建，加方向后缀区分
                        if (t == "ST") name += (item.d == "out" ? "_O" : "_I");
                        if (existing.Contains(name)) continue; // 幂等：跳过已存在规则
                        sb.Append("advfirewall firewall add rule name=\"").Append(name)
                          .Append("\" dir=").Append(item.d)
                          .Append(" action=block program=\"").Append(exe)
                          .Append("\" profile=any enable=yes\r\n");
                        count++;
                    }
                }
                if (count > 0)
                {
                    File.WriteAllText(scriptPath, sb.ToString(), Encoding.ASCII);
                    RunNetshFile(scriptPath);
                    InvalidateRuleCache();
                }
                return count;
            }
            finally { try { File.Delete(scriptPath); } catch { } }
        }

        private static int BlockAllCom(List<string> exes, string tag, Action<string> progress)
        {
            int added = 0;
            HashSet<string> existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var r in ListRules()) existing.Add(r.Item1); } catch { }
            dynamic policy = NewPolicy();
            try
            {
                foreach (string exe in exes)
                {
                    if (tag.Length > 0)
                    {
                        string nOut = RuleName(tag, exe) + (tag == "ST" ? "_O" : "");
                        string nIn = RuleName(tag, exe) + (tag == "ST" ? "_I" : "");
                        if (!existing.Contains(nOut)) AddOne(policy, nOut, exe, DIR_OUT, tag);
                        if (!existing.Contains(nIn)) AddOne(policy, nIn, exe, DIR_IN, tag);
                    }
                    else
                    {
                        if (!existing.Contains(RuleName("OC", exe)))
                            AddOne(policy, RuleName("OC", exe), exe, DIR_OUT, "OC");
                        if (!existing.Contains(RuleName("IA", exe)))
                            AddOne(policy, RuleName("IA", exe), exe, DIR_IN, "IA");
                    }
                    if (progress != null) progress(exe);
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(policy);
                InvalidateRuleCache();
            }
            return added;
        }

        // ---- 规则查询/缓存（netsh 文本解析，不依赖 COM，避免大规则库挂起）----
        private static List<Tuple<string, string, string>> _ruleCache;
        private static DateTime _ruleCacheTime;

        public static void InvalidateRuleCache() { _ruleCache = null; }

        public static List<Tuple<string, string, string>> ListRules()
        {
            if (_ruleCache != null && (DateTime.Now - _ruleCacheTime).TotalSeconds < 60)
                return _ruleCache;
            List<Tuple<string, string, string>> result = new List<Tuple<string, string, string>>();
            try
            {
                string txt = RunNetshCapture("advfirewall firewall show rule name=all verbose");
                if (!string.IsNullOrEmpty(txt))
                {
                    string[] lines = txt.Split('\n');
                    string curName = null; string curExe = null;
                    foreach (string line in lines)
                    {
                        string t = line.Trim();
                        // 兼容英文/中文系统输出
                        if (t.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase) ||
                            t.StartsWith("规则名称:", StringComparison.OrdinalIgnoreCase))
                        {
                            if (curName != null && curName.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase))
                            {
                                string body = curName.Substring(PREFIX.Length);
                                int idx = body.IndexOf('_');
                                string tag = idx > 0 ? body.Substring(0, idx) : "?";
                                result.Add(Tuple.Create(curName, string.IsNullOrEmpty(curExe) ? curName : curExe, tag));
                            }
                            curName = t.Substring(t.IndexOf(':') + 1).Trim();
                            curExe = null;
                        }
                        else if ((t.StartsWith("Program:", StringComparison.OrdinalIgnoreCase) ||
                                  t.StartsWith("程序:", StringComparison.OrdinalIgnoreCase)) && curName != null)
                        {
                            string p = t.Substring(t.IndexOf(':') + 1).Trim();
                            if (p.Length > 0 && !p.Equals("Any", StringComparison.OrdinalIgnoreCase)
                                && !p.Equals("任何", StringComparison.OrdinalIgnoreCase))
                                curExe = p;
                        }
                    }
                    if (curName != null && curName.StartsWith(PREFIX, StringComparison.OrdinalIgnoreCase))
                    {
                        string body = curName.Substring(PREFIX.Length);
                        int idx = body.IndexOf('_');
                        string tag = idx > 0 ? body.Substring(0, idx) : "?";
                        result.Add(Tuple.Create(curName, string.IsNullOrEmpty(curExe) ? curName : curExe, tag));
                    }
                }
            }
            catch { }
            _ruleCache = result;
            _ruleCacheTime = DateTime.Now;
            return result;
        }

        // 单条规则是否存在（netsh show；判断依据=输出中是否包含规则名，语言无关）
        public static bool RuleExists(string ruleName)
        {
            try
            {
                string s = RunNetshCapture("advfirewall firewall show rule name=\"" + ruleName + "\"");
                return !string.IsNullOrEmpty(s) &&
                       s.IndexOf(ruleName, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch { return false; }
        }

        // 单条添加（netsh）
        public static bool AddRuleNetsh(string ruleName, string dir, string exePath)
        {
            try
            {
                bool ok = RunNetsh("advfirewall firewall add rule name=\"" + ruleName + "\" dir=" + dir +
                    " action=block program=\"" + exePath + "\" profile=any enable=yes");
                if (ok) InvalidateRuleCache();
                return ok;
            }
            catch { return false; }
        }

        public static int BlockExe(string exePath)
        {
            int n = 0;
            foreach (var item in new[] { new { d = "out", t = "OC" }, new { d = "in", t = "IA" } })
            {
                string name = RuleName(item.t, exePath);
                if (RuleExists(name)) continue;   // 查重：防止重复创建同名规则
                if (AddRuleNetsh(name, item.d, exePath)) n++;
            }
            return n;
        }

        // 封禁系统网络工具（System32 + SysWOW64 下存在的）
        public static int BlockSystemTools(Action<string> progress = null)
        {
            List<string> exes = new List<string>();
            List<string> dirs = new List<string>();
            try { dirs.Add(Environment.GetFolderPath(Environment.SpecialFolder.System)); } catch { }
            try
            {
                string sysX86 = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                if (!string.IsNullOrEmpty(sysX86) && !dirs.Contains(sysX86)) dirs.Add(sysX86);
            }
            catch { }
            foreach (string dir in dirs)
                foreach (string name in SystemToolNames)
                {
                    string p = Path.Combine(dir, name);
                    if (File.Exists(p)) exes.Add(p);
                }
            return BlockAllTag(exes, "ST", progress);
        }

        // 解除系统网络工具规则
        public static int UnblockSystemTools()
        {
            var names = ListRules().Where(r => r.Item3 == "ST").Select(r => r.Item1).ToList();
            return DeleteRules(names);
        }

        // 当前指定标签的规则总数（用于显示"已有多少条"）
        public static int CountRulesByTag(string tag)
        {
            try { return ListRules().Count(r => r.Item3 == tag); }
            catch { return 0; }
        }

        private static void RunNetshFile(string scriptPath)
        {
            System.Diagnostics.ProcessStartInfo psi =
                new System.Diagnostics.ProcessStartInfo("netsh.exe", "-f \"" + scriptPath + "\"");
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.WaitForExit();
            }
        }

        public static int DeleteRules(IEnumerable<string> ruleNames)
        {
            List<string> names = ruleNames as List<string> ?? ruleNames.ToList();
            if (names.Count == 0) return 0;
            string scriptPath = Path.Combine(Path.GetTempPath(), "DirNetBlock_del_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                StringBuilder sb = new StringBuilder();
                foreach (string name in names)
                    sb.Append("advfirewall firewall delete rule name=\"").Append(name).Append("\"\r\n");
                File.WriteAllText(scriptPath, sb.ToString(), Encoding.ASCII);
                RunNetshFile(scriptPath);
                InvalidateRuleCache(); // 删除后立即失效缓存，否则界面刷新读到旧列表（显示未解封）
                return names.Count;
            }
            finally { try { File.Delete(scriptPath); } catch { } }
        }

        public static bool DeleteRule(string ruleName)
        {
            return DeleteRules(new[] { ruleName }) > 0;
        }
    }

    // ============================ 子进程自动封禁 ============================
// 事件驱动（Win32_ProcessStartTrace 进程创建即触发）+ 轮询兜底：
// 新进程的父进程链中出现"目标目录内程序" → 立即封禁该进程 exe（拉起即封）
public class ChildProcessGuard : IDisposable
{
    // ---- 原生进程枚举 API（不依赖 WMI，稳定可靠）----
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [DllImport("kernel32.dll")]
    private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
    [DllImport("kernel32.dll")]
    private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    private volatile bool _running;
    private Thread _pollThread;
    private List<string> _targetDirs = new List<string>();
    private HashSet<string> _blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private object _lock = new object();
    private Dictionary<uint, Tuple<string, uint>> _prevProcs = new Dictionary<uint, Tuple<string, uint>>(); // 上一轮快照（父进程刚退出时回溯用）
    public int BlockedCount { get; private set; }
    public Action<string> OnBlocked { get; set; }

    public void Start(string targetDir)
    {
        Start(new List<string> { targetDir });
    }

    public void Start(List<string> targetDirs)
    {
        Stop();
        _targetDirs = (targetDirs == null || targetDirs.Count == 0)
            ? new List<string>()
            : new List<string>(targetDirs);
        _blocked.Clear();
        BlockedCount = 0;
        _running = true;

        // 原生轮询：0.3s 一次，可靠且快
        _pollThread = new Thread(PollLoop);
        _pollThread.IsBackground = true;
        _pollThread.Name = "DirNetBlock-GuardPoll";
        _pollThread.Start();
        Log("guard started: dirs=" + _targetDirs.Count);
    }

    // 获取进程完整路径（原生）
    private static string GetExePath(uint pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            StringBuilder sb = new StringBuilder(1024);
            uint size = 1024;
            if (QueryFullProcessImageName(h, 0, sb, ref size)) return sb.ToString();
            return null;
        }
        finally { CloseHandle(h); }
    }

    // 全量进程表：pid -> (exe路径, 父pid)
    private static Dictionary<uint, Tuple<string, uint>> QueryAll()
    {
        Dictionary<uint, Tuple<string, uint>> result = new Dictionary<uint, Tuple<string, uint>>();
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return result;
        try
        {
            PROCESSENTRY32 entry = new PROCESSENTRY32();
            entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
            if (!Process32First(snap, ref entry)) return result;
            do
            {
                if (entry.th32ProcessID != 0)
                {
                    string exe = GetExePath(entry.th32ProcessID);
                    result[entry.th32ProcessID] = Tuple.Create(exe ?? "", entry.th32ParentProcessID);
                }
            }
            while (Process32Next(snap, ref entry));
        }
        finally { CloseHandle(snap); }
        return result;
    }

    private bool IsTargetDir(string exe)
    {
        foreach (string dir in _targetDirs)
        {
            if (!string.IsNullOrEmpty(dir) &&
                exe.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // 诊断日志（写 %TEMP%\DirNetBlock_guard.log，方便排错）
    private static void Log(string msg)
    {
        try
        {
            string p = Path.Combine(Path.GetTempPath(), "DirNetBlock_guard.log");
            using (var sw = File.AppendText(p))
                sw.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " " + msg);
        }
        catch { }
    }

    private bool IsDescendantOfTarget(uint startPid)
    {
        uint cur = startPid;
        for (int depth = 0; depth < 12 && cur != 0; depth++)
        {
            var info = GetProcInfoNative(cur);
            if (info == null) return false;
            if (!string.IsNullOrEmpty(info.Item1) && IsTargetDir(info.Item1))
                return true;
            cur = info.Item2;
        }
        return false;
    }

    private static bool IsConhost(string exe)
    {
        try { return exe.EndsWith("\\conhost.exe", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    // 按 PID 查 exe 路径 + 父 PID（原生快照）
    private static Tuple<string, uint> GetProcInfoNative(uint pid)
    {
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return null;
        try
        {
            PROCESSENTRY32 entry = new PROCESSENTRY32();
            entry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
            if (Process32First(snap, ref entry))
            {
                do
                {
                    if (entry.th32ProcessID == pid)
                    {
                        string exe = GetExePath(pid);
                        return Tuple.Create(exe ?? "", entry.th32ParentProcessID);
                    }
                }
                while (Process32Next(snap, ref entry));
            }
        }
        finally { CloseHandle(snap); }
        return null;
    }

    private bool TryMarkBlocked(string exe)
    {
        lock (_lock)
        {
            if (_blocked.Contains(exe)) return false;
            _blocked.Add(exe);
            return true;
        }
    }

    private void BlockAndNotify(string exe)
    {
        BlockedCount++;
        if (OnBlocked != null) { try { OnBlocked(exe); } catch { } }
        // 异步执行封禁（show 查重 + add 各需 1-2s），不阻塞轮询线程
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                int n = Firewall.BlockExe(exe);
                Log("block async ok: " + exe + " added=" + n);
            }
            catch (Exception ex) { Log("block async error: " + ex.Message); }
        });
    }

    private void PollLoop()
    {
        while (_running)
        {
            try
            {
                Dictionary<uint, Tuple<string, uint>> procs = QueryAll();
                foreach (var kv in procs)
                {
                    if (!_running) break;
                    string exe = kv.Value.Item1;
                    if (string.IsNullOrEmpty(exe)) continue;
                    if (IsTargetDir(exe)) continue;
                    if (IsConhost(exe)) continue;
                    bool isDescendant = false;
                    uint cur = kv.Value.Item2;
                    for (int depth = 0; depth < 12 && cur != 0; depth++)
                    {
                        Tuple<string, uint> parent;
                        if (procs.TryGetValue(cur, out parent))
                        {
                            if (!string.IsNullOrEmpty(parent.Item1) && IsTargetDir(parent.Item1))
                            { isDescendant = true; break; }
                            cur = parent.Item2;
                        }
                        else if (_prevProcs.TryGetValue(cur, out parent))
                        {
                            // 父进程刚退出（如 notepad 商店版重定向器）：用上一轮快照续链
                            if (!string.IsNullOrEmpty(parent.Item1) && IsTargetDir(parent.Item1))
                            { isDescendant = true; break; }
                            cur = parent.Item2;
                        }
                        else break;
                    }
                    if (isDescendant && TryMarkBlocked(exe)) BlockAndNotify(exe);
                }
                _prevProcs = procs; // 供下轮回溯
            }
            catch (Exception ex) { Log("poll loop error: " + ex.Message); }
            for (int i = 0; i < 6 && _running; i++) Thread.Sleep(50); // 0.3s 周期
        }
    }

    public void Stop()
    {
        _running = false;
        if (_pollThread != null)
        {
            try { _pollThread.Join(2000); } catch { }
            _pollThread = null;
        }
    }

    public void Dispose() { Stop(); }
}
// ============================ 图形界面 ============================
    public class MainForm : Form
    {
        private Button btnSelect;
        private Button btnBlock;
        private Button btnUnblockAll;
        private Button btnUnblockSel;
        private CheckBox chkSysTools;
        private CheckBox chkChildGuard;
        private CheckBox chkAutoStart;
        private ListView list;
        private StatusStrip statusStrip;
        private ToolStripStatusLabel statusLabel;
        private Label lblDirs;
        private ListBox lstDirs;
        private Button btnRemoveDir;
        private Button btnUnblockDir;
        private List<string> _dirs = new List<string>(); // 封禁目录列表
        private ChildProcessGuard guard = new ChildProcessGuard();
        private List<string> _autoBlockedExes = new List<string>(); // 被自动封禁的子进程
        private NotifyIcon trayIcon;
        private bool _allowExit = false;

        public MainForm(bool autoStart)
        {
            Text = "目录级内核封网工具 DirNetBlock";
            Font = new Font("Microsoft YaHei UI", 9F);
            ClientSize = new Size(860, 570);
            StartPosition = FormStartPosition.CenterScreen;

            btnSelect = new Button();
            btnSelect.Text = "添加目录…";
            btnSelect.Location = new Point(12, 38);
            btnSelect.Size = new Size(100, 30);
            btnSelect.Click += delegate { AddDir(); };

            btnBlock = new Button();
            btnBlock.Text = "封禁联网";
            btnBlock.Location = new Point(122, 38);
            btnBlock.Size = new Size(100, 30);
            btnBlock.BackColor = Color.FromArgb(232, 17, 35);
            btnBlock.ForeColor = Color.White;
            btnBlock.FlatStyle = FlatStyle.Flat;
            btnBlock.Click += delegate { BlockAsync(); };

            btnUnblockSel = new Button();
            btnUnblockSel.Text = "解除选中";
            btnUnblockSel.Location = new Point(232, 38);
            btnUnblockSel.Size = new Size(100, 30);
            btnUnblockSel.Click += delegate { UnblockSelectedAsync(); };

            btnUnblockAll = new Button();
            btnUnblockAll.Text = "全部解除";
            btnUnblockAll.Location = new Point(342, 38);
            btnUnblockAll.Size = new Size(100, 30);
            btnUnblockAll.Click += delegate { UnblockAllAsync(); };

            chkSysTools = new CheckBox();
            chkSysTools.Text = "同时封禁系统网络工具(curl/certutil等17个)";
            chkSysTools.Location = new Point(12, 76);
            chkSysTools.AutoSize = true;
            chkSysTools.Checked = true;

            chkChildGuard = new CheckBox();
            chkChildGuard.Text = "子进程自动封禁(拉起即封)";
            chkChildGuard.Location = new Point(340, 76);
            chkChildGuard.AutoSize = true;
            chkChildGuard.Checked = true;

            chkAutoStart = new CheckBox();
            chkAutoStart.Text = "开机自启";
            chkAutoStart.Location = new Point(660, 76);
            chkAutoStart.AutoSize = true;
            chkAutoStart.Checked = Config.GetAutoStart();
            chkAutoStart.Click += delegate { Config.SetAutoStart(chkAutoStart.Checked); SetStatus(chkAutoStart.Checked ? "开机自启已开启" : "开机自启已关闭"); };

            lblDirs = new Label();
            lblDirs.Text = "封禁目录（可添加多个）：";
            lblDirs.Location = new Point(12, 106);
            lblDirs.AutoSize = true;
            lblDirs.ForeColor = Color.DimGray;

            lstDirs = new ListBox();
            lstDirs.Location = new Point(12, 126);
            lstDirs.Size = new Size(500, 108);
            lstDirs.HorizontalScrollbar = true;

            btnRemoveDir = new Button();
            btnRemoveDir.Text = "移除选中目录";
            btnRemoveDir.Location = new Point(520, 126);
            btnRemoveDir.Size = new Size(100, 30);
            btnRemoveDir.Click += delegate { RemoveDir(); };

            btnUnblockDir = new Button();
            btnUnblockDir.Text = "解除选中目录";
            btnUnblockDir.Location = new Point(630, 126);
            btnUnblockDir.Size = new Size(100, 30);
            btnUnblockDir.Click += delegate { UnblockDirAsync(); };

            list = new ListView();
            list.Location = new Point(12, 246);
            list.Size = new Size(836, 282);
            list.View = View.Details;
            list.FullRowSelect = true;
            list.GridLines = true;
            list.Columns.Add("程序文件", 560);
            list.Columns.Add("状态", 140);
            list.Columns.Add("规则名", 120);

            statusStrip = new StatusStrip();
            statusLabel = new ToolStripStatusLabel("就绪");
            statusStrip.Items.Add(statusLabel);

            Controls.Add(lblDirs);
            Controls.Add(lstDirs);
            Controls.Add(btnRemoveDir);
            Controls.Add(btnUnblockDir);
            Controls.Add(btnSelect);
            Controls.Add(btnBlock);
            Controls.Add(btnUnblockSel);
            Controls.Add(btnUnblockAll);
            Controls.Add(chkSysTools);
            Controls.Add(chkChildGuard);
            Controls.Add(chkAutoStart);
            Controls.Add(list);
            Controls.Add(statusStrip);

            // 系统托盘：关闭窗口 → 最小化到托盘后台运行
            trayIcon = new NotifyIcon();
            trayIcon.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
            trayIcon.Text = "DirNetBlock 目录封网工具";
            trayIcon.Visible = true;
            trayIcon.DoubleClick += delegate { ShowMain(); };
            ContextMenuStrip trayMenu = new ContextMenuStrip();
            trayMenu.Items.Add("显示主界面", null, delegate { ShowMain(); });
            ToolStripMenuItem miAuto = new ToolStripMenuItem("开机自启");
            miAuto.Checked = Config.GetAutoStart();
            miAuto.Click += delegate { miAuto.Checked = !miAuto.Checked; Config.SetAutoStart(miAuto.Checked); };
            trayMenu.Items.Add(miAuto);
            trayMenu.Items.Add(new ToolStripSeparator());
            trayMenu.Items.Add("退出", null, delegate { _allowExit = true; Close(); });
            trayIcon.ContextMenuStrip = trayMenu;

            this.FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                if (!_allowExit)
                {
                    e.Cancel = true;
                    this.Hide();
                    this.ShowInTaskbar = false;
                    trayIcon.ShowBalloonTip(1500, "DirNetBlock", "已最小化到托盘，后台继续运行。右键托盘图标可退出。", ToolTipIcon.Info);
                }
                else
                {
                    guard.Stop();
                    trayIcon.Visible = false;
                }
            };

            // 恢复上次封禁状态
            Config.Load();
            foreach (string dir in Config.Dirs)
            {
                if (Directory.Exists(dir) && !_dirs.Contains(dir, StringComparer.OrdinalIgnoreCase))
                    _dirs.Add(dir);
            }
            foreach (string dir in _dirs) lstDirs.Items.Add(dir);
            chkSysTools.Checked = Config.SysTools;
            chkChildGuard.Checked = Config.ChildGuard;
            // 恢复上次自动封禁的子进程记录
            foreach (string exe in Config.AutoBlocked)
                if (!_autoBlockedExes.Contains(exe, StringComparer.OrdinalIgnoreCase))
                    _autoBlockedExes.Add(exe);
            if (lstDirs.Items.Count > 0 || _autoBlockedExes.Count > 0) RefreshList();
            if (autoStart)
            {
                // 开机自启：后台运行，不显示窗口
                this.WindowState = FormWindowState.Minimized;
                this.ShowInTaskbar = false;
                this.Hide();
                AutoRestore();
            }
            else
            {
                this.ShowInTaskbar = true;
            }

            if (!Firewall.IsAdmin())
            {
                SetStatus("警告：未以管理员身份运行，封禁可能失败！请右键→以管理员身份运行。");
                btnBlock.Enabled = false;
                btnUnblockAll.Enabled = false;
                btnUnblockSel.Enabled = false;
            }
            else
            {
                RefreshList();
                // 打开界面即启动子进程监视（有目录且开启子进程封禁时），无需先点"封禁联网"
                if (_dirs.Count > 0 && Config.ChildGuard)
                {
                    guard.OnBlocked = delegate(string exe)
                    {
                        SetStatus("子进程监视中: 已自动封禁 " + exe);
                        if (!_autoBlockedExes.Contains(exe, StringComparer.OrdinalIgnoreCase))
                        {
                            _autoBlockedExes.Add(exe);
                            Config.AutoBlocked = new List<string>(_autoBlockedExes);
                            Config.Save();
                        }
                        AddAutoBlockedRow(exe);
                    };
                    guard.Start(new List<string>(_dirs));
                    SetStatus("子进程监视已开启：运行目录中的程序，其拉起的子进程将自动封禁并显示在列表");
                }
            }
        }

        private void ShowMain()
        {
            this.Show();
            this.ShowInTaskbar = true;
            this.WindowState = FormWindowState.Normal;
            this.BringToFront();
        }

        // 子进程被自动封禁时，实时追加到列表（插入"自动封禁的子进程"分组之后）
        private void AddAutoBlockedRow(string exe)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(AddAutoBlockedRow), exe); return; }
            try
            {
                foreach (ListViewItem it in list.Items)
                    if (it.Text.Equals(exe, StringComparison.OrdinalIgnoreCase)) return;
                ListViewItem ni = new ListViewItem(exe);
                ni.SubItems.Add("已封禁（子进程自动）");
                ni.SubItems.Add(Firewall.RuleName("OC", exe));
                ni.ForeColor = Color.FromArgb(178, 34, 34);
                int insertIdx = -1;
                for (int i = list.Items.Count - 1; i >= 0; i--)
                {
                    string tag = list.Items[i].Tag as string;
                    if (tag == "childgroup") { insertIdx = i + 1; break; }
                }
                if (insertIdx >= 0 && insertIdx < list.Items.Count)
                    list.Items.Insert(insertIdx, ni);
                else if (insertIdx >= 0)
                    list.Items.Add(ni);
                else
                    list.Items.Add(ni);
            }
            catch { }
        }

        private void SetStatus(string s)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(SetStatus), s); return; }
            statusLabel.Text = s;
        }

        private void AddDir()
        {
            FolderBrowserDialog dlg = new FolderBrowserDialog();
            dlg.Description = "选择要禁止联网的目录（可添加多个）";
            dlg.ShowNewFolderButton = false;
            if (dlg.ShowDialog(this) == DialogResult.OK)
            {
                string dir = dlg.SelectedPath;
                if (_dirs.Contains(dir, StringComparer.OrdinalIgnoreCase))
                {
                    SetStatus("该目录已在列表中: " + dir);
                    return;
                }
                _dirs.Add(dir);
                lstDirs.Items.Add(dir);
                RefreshList();
                SetStatus("已添加目录，共 " + _dirs.Count + " 个目录");
            }
        }

        private void RemoveDir()
        {
            if (lstDirs.SelectedItem == null) { SetStatus("请先在列表选中要移除的目录"); return; }
            string dir = lstDirs.SelectedItem.ToString();
            _dirs.RemoveAll(d => d.Equals(dir, StringComparison.OrdinalIgnoreCase));
            lstDirs.Items.Remove(dir);
            RefreshList();
            SetStatus("已从管理列表移除（原有封禁规则保留，可用「解除选中目录」删除规则）: " + dir);
        }

        // 一次性解除整个目录：删除该目录下所有 exe 的规则 + 从管理列表移除
        private async void UnblockDirAsync()
        {
            if (lstDirs.SelectedItem == null) { SetStatus("请先在目录列表选中要解除的目录"); return; }
            string dir = lstDirs.SelectedItem.ToString();
            if (MessageBox.Show(this, "确定解除目录 " + dir + " 的全部封禁规则并移除吗？\n（该目录下所有程序将恢复联网）",
                "确认解除目录", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            btnUnblockDir.Enabled = false;
            SetStatus("正在解除目录: " + dir + " …");
            int n = await Task.Run(() =>
            {
                var rules = Firewall.ListRules();
                var names = rules.Where(r => r.Item2.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                                 .Select(r => r.Item1).ToList();
                return Firewall.DeleteRules(names);
            });
            _dirs.RemoveAll(d => d.Equals(dir, StringComparison.OrdinalIgnoreCase));
            lstDirs.Items.Remove(dir);
            Config.Dirs = new List<string>(_dirs);
            Config.Save();
            // 同步子进程监视：该目录不再监视；目录清空则停止
            if (_dirs.Count > 0 && chkChildGuard.Checked)
                guard.Start(new List<string>(_dirs));
            else if (_dirs.Count == 0)
                guard.Stop();
            SetStatus("已解除目录 " + dir + "，删除 " + n + " 条规则");
            RefreshList();
            btnUnblockDir.Enabled = true;
        }

        private void RefreshList()
        {
            list.Items.Clear();
            var rules = Firewall.ListRules();
            Dictionary<string, List<string>> ruleMap =
                new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rules)
            {
                if (string.IsNullOrEmpty(r.Item2)) continue;
                if (!ruleMap.ContainsKey(r.Item2)) ruleMap[r.Item2] = new List<string>();
                ruleMap[r.Item2].Add(r.Item1);
            }
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            // 1) 封禁目录区（每个目录一个分组标题，其下列出程序）
            foreach (string dir in _dirs)
            {
                List<string> exes = Firewall.EnumerateExes(dir);
                ListViewItem grp = new ListViewItem("目录: " + dir);
                grp.Tag = "dirgroup";
                grp.SubItems.Add(exes.Count + " 个程序");
                grp.SubItems.Add("-");
                grp.BackColor = Color.FromArgb(242, 242, 242);
                grp.Font = new Font(list.Font, FontStyle.Bold);
                list.Items.Add(grp);
                foreach (string exe in exes)
                {
                    if (!seen.Add(exe)) continue;
                    ListViewItem it = new ListViewItem(exe);
                    if (ruleMap.ContainsKey(exe))
                    {
                        var names = ruleMap[exe];
                        bool both = names.Count >= 2;
                        it.SubItems.Add(both ? "已封禁（出站+入站）" : "已封禁");
                        it.SubItems.Add(names.Count > 0 ? names[0] : "-");
                        it.ForeColor = Color.Gray;
                    }
                    else
                    {
                        it.SubItems.Add("未封禁");
                        it.SubItems.Add("-");
                    }
                    list.Items.Add(it);
                }
            }
            // 2) 系统网络工具区（ST 规则，蓝字）
            List<string> stExes = rules
                .Where(r => r.Item3 == "ST" && !string.IsNullOrEmpty(r.Item2))
                .Select(r => r.Item2)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(e => e, StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (stExes.Count > 0)
            {
                ListViewItem grp = new ListViewItem("系统网络工具（已封禁）");
                grp.Tag = "stgroup";
                grp.SubItems.Add(stExes.Count + " 个工具");
                grp.SubItems.Add("-");
                grp.BackColor = Color.FromArgb(224, 240, 255);
                grp.Font = new Font(list.Font, FontStyle.Bold);
                list.Items.Add(grp);
                foreach (string exe in stExes)
                {
                    if (!seen.Add(exe)) continue;
                    ListViewItem it = new ListViewItem(exe);
                    it.SubItems.Add("已封禁（系统工具）");
                    it.SubItems.Add(ruleMap.ContainsKey(exe) ? ruleMap[exe][0] : "-");
                    it.ForeColor = Color.FromArgb(0, 102, 204);
                    list.Items.Add(it);
                }
            }
            // 3) 自动封禁的子进程区（目标目录程序拉起的，红字；无记录时显示空态提示）
            List<string> childExes = new List<string>();
            foreach (string exe in _autoBlockedExes)
            {
                bool inDirs = false;
                foreach (string dir in _dirs)
                    if (exe.StartsWith(dir, StringComparison.OrdinalIgnoreCase)) { inDirs = true; break; }
                if (!inDirs) childExes.Add(exe);
            }
            ListViewItem cgrp = new ListViewItem(childExes.Count > 0 ? "自动封禁的子进程" : "自动封禁的子进程（暂无）");
            cgrp.Tag = "childgroup";
            cgrp.SubItems.Add(childExes.Count > 0 ? childExes.Count + " 个" : "运行目录中的程序后会实时出现");
            cgrp.SubItems.Add("-");
            cgrp.BackColor = Color.FromArgb(255, 232, 232);
            cgrp.Font = new Font(list.Font, FontStyle.Bold);
            list.Items.Add(cgrp);
            foreach (string exe in childExes)
            {
                ListViewItem it = new ListViewItem(exe);
                if (ruleMap.ContainsKey(exe))
                {
                    it.SubItems.Add("已封禁（子进程自动）");
                    it.SubItems.Add(ruleMap[exe][0]);
                    it.ForeColor = Color.FromArgb(178, 34, 34);
                }
                else
                {
                    it.SubItems.Add("子进程（已解除）");
                    it.SubItems.Add("-");
                    it.ForeColor = Color.Gray;
                }
                list.Items.Add(it);
            }
        }

        // 开机自启恢复：检查/补全规则 + 重新开启子进程监视
        private async void AutoRestore()
        {
            if (Config.Dirs.Count == 0)
            {
                SetStatus("开机自启: 未找到上次封禁的目录，等待配置");
                return;
            }
            List<string> dirs = new List<string>();
            foreach (string dir in Config.Dirs)
                if (Directory.Exists(dir)) dirs.Add(dir);
            if (dirs.Count == 0)
            {
                SetStatus("开机自启: 上次封禁的目录已不存在，跳过恢复");
                return;
            }
            SetStatus("开机自启恢复: " + string.Join(" ; ", dirs) + " …");
            bool fwOk = await Task.Run(() => Firewall.EnsureFirewallOn());
            if (!fwOk)
            {
                SetStatus("警告: Windows 防火墙未能开启，恢复中止（可能被安全软件/域策略控制）");
                return;
            }
            List<string> allExes = new List<string>();
            foreach (string dir in dirs)
            {
                List<string> exes = Firewall.EnumerateExes(dir);
                foreach (string e in exes)
                    if (!allExes.Contains(e, StringComparer.OrdinalIgnoreCase)) allExes.Add(e);
            }
            // 子进程监视在封禁前启动，保证任何时刻拉起的子进程都不被错过
            if (Config.ChildGuard)
            {
                guard.OnBlocked = delegate(string exe)
                {
                    SetStatus("子进程监视中: 已自动封禁 " + exe);
                    if (!_autoBlockedExes.Contains(exe, StringComparer.OrdinalIgnoreCase))
                    {
                        _autoBlockedExes.Add(exe);
                        Config.AutoBlocked = new List<string>(_autoBlockedExes);
                        Config.Save();
                    }
                    AddAutoBlockedRow(exe);
                };
                guard.Start(dirs);
            }
            int ok = 0;
            if (allExes.Count > 0)
                ok = await Task.Run(() => Firewall.BlockAll(allExes));
            int sysOk = 0;
            if (Config.SysTools)
            {
                int stBefore = Firewall.CountRulesByTag("ST");
                sysOk = await Task.Run(() => Firewall.BlockSystemTools());
                SetStatus("系统工具已封禁: 本次新增 " + sysOk + " 条，当前共 " + (stBefore + sysOk) + " 条");
            }
            SetStatus("开机自启恢复完成: 目录 " + ok + " 条 + 系统工具 " + sysOk + " 条规则"
                + (Config.ChildGuard ? "，子进程监视已开启" : ""));
            RefreshList();
        }

        private async void BlockAsync()
        {
            if (_dirs.Count == 0) { SetStatus("请先添加要封禁的目录"); return; }
            // 汇总所有目录的 exe
            List<string> allExes = new List<string>();
            int dirCount = 0;
            foreach (string dir in _dirs)
            {
                List<string> exes = Firewall.EnumerateExes(dir);
                if (exes.Count > 0) dirCount++;
                foreach (string e in exes)
                    if (!allExes.Contains(e, StringComparer.OrdinalIgnoreCase)) allExes.Add(e);
            }
            if (allExes.Count == 0) { SetStatus("所选目录下没有 exe 文件"); return; }
            btnBlock.Enabled = false;
            btnUnblockAll.Enabled = false;
            btnUnblockSel.Enabled = false;
            guard.Stop();
            SetStatus("检查并开启 Windows 防火墙…");
            bool fwOk = await Task.Run(() => Firewall.EnsureFirewallOn());
            if (!fwOk)
            {
                SetStatus("警告：Windows 防火墙未能开启（可能被安全软件/域策略控制），封禁不会生效！");
                btnBlock.Enabled = true;
                btnUnblockAll.Enabled = true;
                btnUnblockSel.Enabled = true;
                return;
            }
            SetStatus("防火墙已开启，正在封禁 " + dirCount + " 个目录共 " + allExes.Count + " 个程序…");
            // 子进程监视在封禁前启动，保证任何时刻拉起的子进程都不被错过
            if (chkChildGuard.Checked)
            {
                guard.OnBlocked = delegate(string exe)
                {
                    SetStatus("子进程监视中: 已自动封禁 " + exe);
                    if (!_autoBlockedExes.Contains(exe, StringComparer.OrdinalIgnoreCase))
                    {
                        _autoBlockedExes.Add(exe);
                        Config.AutoBlocked = new List<string>(_autoBlockedExes);
                        Config.Save();
                    }
                    AddAutoBlockedRow(exe);
                };
                guard.Start(new List<string>(_dirs));
            }
            int ok = await Task.Run(() => Firewall.BlockAll(allExes));
            int sysOk = 0;
            if (chkSysTools.Checked)
            {
                SetStatus("正在封禁系统网络工具…");
                int stBefore = Firewall.CountRulesByTag("ST");
                sysOk = await Task.Run(() => Firewall.BlockSystemTools());
                SetStatus("系统工具已封禁: 本次新增 " + sysOk + " 条，当前共 " + (stBefore + sysOk) + " 条");
            }
            SetStatus("封禁完成: 目录 " + ok + " 条 + 系统工具 " + sysOk + " 条规则"
                + (chkChildGuard.Checked ? "，子进程监视已开启" : ""));
            Config.Dirs = new List<string>(_dirs);
            Config.SysTools = chkSysTools.Checked;
            Config.ChildGuard = chkChildGuard.Checked;
            Config.Save();
            RefreshList();
            btnBlock.Enabled = true;
            btnUnblockAll.Enabled = true;
            btnUnblockSel.Enabled = true;
        }

        private async void UnblockSelectedAsync()
        {
            List<string> paths = new List<string>();
            foreach (ListViewItem it in list.SelectedItems)
            {
                string tag = it.Tag as string;
                if (tag != null && tag.EndsWith("group")) continue; // 跳过目录/分区标题行
                paths.Add(it.Text);
            }
            if (paths.Count == 0) { SetStatus("请先选中要解除的程序（分区标题不可选）"); return; }
            btnUnblockSel.Enabled = false;
            SetStatus("正在解除选中的 " + paths.Count + " 个程序，请稍候…");
            int n = await Task.Run(() =>
            {
                var rules = Firewall.ListRules();
                var names = rules.Where(r => paths.Contains(r.Item2, StringComparer.OrdinalIgnoreCase))
                                 .Select(r => r.Item1).ToList();
                return Firewall.DeleteRules(names);
            });
            SetStatus("已解除选中程序，共删除 " + n + " 条规则");
            RefreshList();
            btnUnblockSel.Enabled = true;
        }

        private async void UnblockAllAsync()
        {
            if (MessageBox.Show(this, "确定要解除本工具添加的全部封网规则吗？\n（包括系统网络工具规则和子进程封禁）", "确认",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            guard.Stop();
            btnUnblockAll.Enabled = false;
            SetStatus("正在全部解除，请稍候…");
            int n = await Task.Run(() =>
            {
                var names = Firewall.ListRules().Select(r => r.Item1).ToList();
                return Firewall.DeleteRules(names);
            });
            SetStatus("已全部解除，共删除 " + n + " 条规则");
            Config.Dirs.Clear();
            _autoBlockedExes.Clear();
            Config.AutoBlocked.Clear();
            Config.Save();
            _dirs.Clear();
            lstDirs.Items.Clear();
            RefreshList();
            btnUnblockAll.Enabled = true;
        }
    }

    // ============================ 配置持久化 ============================
    public static class Config
    {
        private static string DirPath
        {
            get
            {
                string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DirNetBlock");
                try { Directory.CreateDirectory(p); } catch { }
                return p;
            }
        }
        private static string FilePath { get { return Path.Combine(DirPath, "config.ini"); } }

        public static List<string> Dirs = new List<string>();
        public static bool SysTools { get; set; }
        public static bool ChildGuard { get; set; }
        public static List<string> AutoBlocked = new List<string>(); // 被自动封禁的子进程（持久化）

        public static void Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return;
                foreach (string line in File.ReadAllLines(FilePath))
                {
                    if (line.StartsWith("Dir=") && line.Length > 4)
                    {
                        string dir = line.Substring(4);
                        if (!Dirs.Contains(dir, StringComparer.OrdinalIgnoreCase))
                            Dirs.Add(dir);
                    }
                    else if (line.StartsWith("LastDir=") && line.Length > 8) // 兼容旧配置
                    {
                        string dir = line.Substring(8);
                        if (!Dirs.Contains(dir, StringComparer.OrdinalIgnoreCase))
                            Dirs.Add(dir);
                    }
                    else if (line.StartsWith("SysTools=")) SysTools = line.Substring(9) == "1";
                    else if (line.StartsWith("ChildGuard=")) ChildGuard = line.Substring(11) == "1";
                    else if (line.StartsWith("AutoBlocked=") && line.Length > 12)
                    {
                        string exe = line.Substring(12);
                        if (!string.IsNullOrEmpty(exe) && !AutoBlocked.Contains(exe, StringComparer.OrdinalIgnoreCase))
                            AutoBlocked.Add(exe);
                    }
                }
            }
            catch { }
        }

        public static void Save()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                foreach (string dir in Dirs)
                    sb.Append("Dir=").Append(dir ?? "").Append("\r\n");
                sb.Append("SysTools=").Append(SysTools ? "1" : "0").Append("\r\n");
                sb.Append("ChildGuard=").Append(ChildGuard ? "1" : "0").Append("\r\n");
                foreach (string exe in AutoBlocked)
                    sb.Append("AutoBlocked=").Append(exe ?? "").Append("\r\n");
                File.WriteAllText(FilePath, sb.ToString());
            }
            catch { }
        }

        public static bool GetAutoStart()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    if (k == null) return false;
                    var v = k.GetValue("DirNetBlock");
                    return v != null && v.ToString().Contains("--autostart");
                }
            }
            catch { return false; }
        }

        public static void SetAutoStart(bool on)
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (k == null) return;
                    if (on)
                    {
                        // 固定注册 GUI 版（DirNetBlock.exe），避免注册到 CLI 版
                        string exeDir = Path.GetDirectoryName(Application.ExecutablePath);
                        string guiPath = Path.Combine(exeDir, "DirNetBlock.exe");
                        if (!File.Exists(guiPath)) guiPath = Application.ExecutablePath;
                        k.SetValue("DirNetBlock", "\"" + guiPath + "\" --autostart");
                    }
                    else k.DeleteValue("DirNetBlock", false);
                }
            }
            catch { }
        }
    }

    // ============================ 命令行 ============================
    public static class Cli
    {
        public static int Run(string[] args)
        {
            try
            {
                switch (args[0])
                {
                    case "--block":
                        {
                            if (args.Length < 2) { Console.WriteLine("用法: --block <目录> [目录2 ...]"); return 2; }
                            List<string> dirs = new List<string>();
                            for (int i = 1; i < args.Length; i++)
                            {
                                if (!Directory.Exists(args[i])) { Console.WriteLine("目录不存在: " + args[i]); return 2; }
                                dirs.Add(args[i]);
                            }
                            List<string> allExes = new List<string>();
                            foreach (string dir in dirs)
                            {
                                var exes = Firewall.EnumerateExes(dir);
                                foreach (string e in exes)
                                    if (!allExes.Contains(e, StringComparer.OrdinalIgnoreCase)) allExes.Add(e);
                            }
                            Console.WriteLine("扫描到 " + dirs.Count + " 个目录共 " + allExes.Count + " 个 exe");
                            Console.WriteLine("检查并开启 Windows 防火墙…");
                            if (!Firewall.EnsureFirewallOn())
                            {
                                Console.WriteLine("错误: 无法开启 Windows 防火墙（可能被安全软件/域策略控制），封禁已中止");
                                return 1;
                            }
                            Console.WriteLine("防火墙已开启，开始封禁…");
                            int ok = Firewall.BlockAll(allExes, exe => Console.WriteLine("  [封禁] " + exe));
                            Console.WriteLine("完成: 成功添加 " + ok + " 条内核规则 (期望 " + allExes.Count * 2 + ")");
                            return 0;
                        }
                    case "--block-hard":
                        {
                            if (args.Length < 2) { Console.WriteLine("用法: --block-hard <目录> [目录2 ...]"); return 2; }
                            List<string> dirs = new List<string>();
                            for (int i = 1; i < args.Length; i++)
                            {
                                if (!Directory.Exists(args[i])) { Console.WriteLine("目录不存在: " + args[i]); return 2; }
                                dirs.Add(args[i]);
                            }
                            List<string> allExes = new List<string>();
                            foreach (string dir in dirs)
                            {
                                var exes = Firewall.EnumerateExes(dir);
                                foreach (string e in exes)
                                    if (!allExes.Contains(e, StringComparer.OrdinalIgnoreCase)) allExes.Add(e);
                            }
                            Console.WriteLine("扫描到 " + dirs.Count + " 个目录共 " + allExes.Count + " 个 exe");
                            Console.WriteLine("检查并开启 Windows 防火墙…");
                            if (!Firewall.EnsureFirewallOn())
                            {
                                Console.WriteLine("错误: 无法开启 Windows 防火墙（可能被安全软件/域策略控制），封禁已中止");
                                return 1;
                            }
                            Console.WriteLine("防火墙已开启，正在封禁目录程序…");
                            // 子进程监视在封禁前启动，保证任何时刻拉起的子进程都不被错过
                            using (var guard = new ChildProcessGuard())
                            {
                                guard.OnBlocked = delegate(string exe) { Console.WriteLine("  [自动封禁子进程] " + exe); };
                                guard.Start(dirs);
                                int ok = Firewall.BlockAll(allExes, exe => Console.WriteLine("  [封禁] " + exe));
                                Console.WriteLine("目录程序已封禁 " + ok + " 条规则");
                                Console.WriteLine("封禁系统网络工具…");
                                int stBefore = Firewall.CountRulesByTag("ST");
                                int sysOk = Firewall.BlockSystemTools();
                                Console.WriteLine("系统网络工具: 本次新增 " + sysOk + " 条，当前共 " + (stBefore + sysOk) + " 条");
                                Console.WriteLine("子进程监视运行中，按 Ctrl+C 停止（退出后规则保留）");
                                while (true) Thread.Sleep(1000);
                            }
                        }
                    case "--unblock":
                        {
                            if (args.Length < 2) { Console.WriteLine("用法: --unblock <目录>"); return 2; }
                            string dir = args[1];
                            var names = Firewall.ListRules()
                                .Where(r => r.Item2.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                                .Select(r => r.Item1).ToList();
                            int c = Firewall.DeleteRules(names);
                            Console.WriteLine("完成: 解除 " + c + " 条规则 (匹配目录 " + dir + ")");
                            return 0;
                        }
                    case "--unblock-all":
                        {
                            var names = Firewall.ListRules().Select(r => r.Item1).ToList();
                            int c = Firewall.DeleteRules(names);
                            Console.WriteLine("完成: 全部解除 " + c + " 条规则");
                            return 0;
                        }
                    case "--unblock-sys":
                        {
                            int c = Firewall.UnblockSystemTools();
                            Console.WriteLine("完成: 解除系统网络工具规则 " + c + " 条");
                            return 0;
                        }
                    case "--autostart-on":
                        Config.SetAutoStart(true);
                        Console.WriteLine("完成: 开机自启已开启");
                        return 0;
                    case "--autostart-off":
                        Config.SetAutoStart(false);
                        Console.WriteLine("完成: 开机自启已关闭");
                        return 0;
                    case "--list":
                        {
                            var rules = Firewall.ListRules();
                            Console.WriteLine("当前 DirNetBlock 规则共 " + rules.Count + " 条:");
                            foreach (var r in rules)
                                Console.WriteLine("  " + r.Item1 + "  =>  " + r.Item2 + "  (" + r.Item3 + ")");
                            return 0;
                        }
                    default:
                        Console.WriteLine("用法:");
                        Console.WriteLine("  DirNetBlock.exe --block <目录>          封禁目录下所有 exe");
                        Console.WriteLine("  DirNetBlock.exe --block-hard <目录>     封目录+系统工具+子进程监视(常驻)");
                        Console.WriteLine("  DirNetBlock.exe --unblock <目录>        解除该目录的规则");
                        Console.WriteLine("  DirNetBlock.exe --unblock-all            解除全部规则");
                        Console.WriteLine("  DirNetBlock.exe --unblock-sys            解除系统网络工具规则");
                        Console.WriteLine("  DirNetBlock.exe --autostart-on           开启开机自启");
                        Console.WriteLine("  DirNetBlock.exe --autostart-off          关闭开机自启");
                        Console.WriteLine("  DirNetBlock.exe --list                   列出全部规则");
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("错误: " + ex.Message);
                return 1;
            }
        }
    }
}