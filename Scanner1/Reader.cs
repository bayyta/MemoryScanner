using System;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace Scanner
{
    class Reader
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_VM_WRITE = 0x0020;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_QUERY_INFORMATION = 0x0400;

        [DllImport("kernel32.dll")]
        public static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UInt32 dwSize, out IntPtr lpNumberOfBytesWritten);

        private IntPtr m_ProcessHandle;
        private Process m_Process;
        private List<IntPtr> memoryAddresses = new List<IntPtr>();
        private int textLength = 0;

        public Reader() { }

        public void OpenProcess(Process process)
        {
            m_Process = process;
            m_ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, true, (uint)process.Id);
        }

        public void OpenProcessRead(Process process)
        {
            m_Process = process;
            m_ProcessHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, true, (uint)process.Id);
        }

        public byte[] ReadProcessMemory(IntPtr memoryAddress, uint bytesToRead, out int bytesRead)
        {
            byte[] buffer = new byte[bytesToRead];

            IntPtr ptrBytesRead;
            ReadProcessMemory(m_ProcessHandle, memoryAddress, buffer, bytesToRead, out ptrBytesRead);

            bytesRead = ptrBytesRead.ToInt32();

            return buffer;

        }

        public void WriteProcessMemory(IntPtr memoryAddress, int value)
        {
            IntPtr bytesWritten;
            byte[] buffer = BitConverter.GetBytes(value);
            WriteProcessMemory(m_ProcessHandle, memoryAddress, buffer, (uint)buffer.Length, out bytesWritten);
        }

        public void WriteInt(int value)
        {
            IntPtr bytesWritten;
            byte[] buffer = BitConverter.GetBytes(value);
            foreach (IntPtr address in memoryAddresses)
            {
                WriteProcessMemory(m_ProcessHandle, address, buffer, (uint)buffer.Length, out bytesWritten);
            }
        }

        public void WriteString(string text)
        {
            IntPtr bytesWritten;
            byte[] buffer = Encoding.ASCII.GetBytes(text);
            int bytesLeftLength = textLength - buffer.Length;
            byte[] bytesLeft = new byte[bytesLeftLength];
            for (int i = 0; i < bytesLeftLength; i++)
            {
                bytesLeft[i] = 0x0;
            }
            foreach (IntPtr address in memoryAddresses)
            {
                WriteProcessMemory(m_ProcessHandle, address + buffer.Length, bytesLeft, (uint)bytesLeftLength, out bytesWritten);
                WriteProcessMemory(m_ProcessHandle, address, buffer, (uint)buffer.Length, out bytesWritten);
            }
        }

        public bool NewScan(int value)
        {
            memoryAddresses.Clear();

            IntPtr bytesRead;
            uint PTR = 0x0;
            int size = 20480;
            uint endMem = 0x7fffffff;
            int valueSize = sizeof(int);
            byte[] buffer = new byte[size];

            while (PTR < endMem)
            {
                ReadProcessMemory(m_ProcessHandle, (IntPtr)PTR, buffer, (uint)buffer.Length, out bytesRead);

                for (int i = 0; i < buffer.Length - valueSize + 1; i++) // (- valueSize + 1) to avoid stackoverflow exception in (BitConverer.ToInt32)
                {
                    int v = BitConverter.ToInt32(buffer, i);
                    if (v == value)
                    {
                        memoryAddresses.Add((IntPtr)(PTR + i));
                    }
                }

                PTR += (uint)(buffer.Length - valueSize + 1); // The last 3 bytes won't get read in the buffer. Therefore decrement with (valueSize + 1)
            }

            return true;
        }





        [DllImport("kernel32.dll")]
        static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int VirtualQueryEx(IntPtr hProcess,
        IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        public struct MEMORY_BASIC_INFORMATION
        {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        const int MEM_COMMIT = 0x00001000;
        const int PAGE_READWRITE = 0x04;

        public bool FastScan(int value)
        {
            memoryAddresses.Clear();

            SYSTEM_INFO sys_info = new SYSTEM_INFO();
            GetSystemInfo(out sys_info);

            IntPtr proc_min_address = (IntPtr)0x0;
            IntPtr proc_max_address = (IntPtr)0x7fefffff;

            // saving the values as long ints so I dont have to do a lot of casts later
            long proc_min_address_l = (long)proc_min_address;
            long proc_max_address_l = (long)proc_max_address;

            // this will store any information we get from VirtualQueryEx()
            MEMORY_BASIC_INFORMATION mem_basic_info = new MEMORY_BASIC_INFORMATION();

            IntPtr bytesRead;  // number of bytes read with ReadProcessMemory

            int maxSize = 20971520;
            byte[] buffer = new byte[maxSize];

            while (proc_min_address_l < proc_max_address_l)
            {
                // 28 = sizeof(MEMORY_BASIC_INFORMATION)
                VirtualQueryEx(m_ProcessHandle, proc_min_address, out mem_basic_info, 28);

                // if this memory chunk is accessible
                if (mem_basic_info.Protect == PAGE_READWRITE && mem_basic_info.State == MEM_COMMIT)
                {
                    for (int i = 0; i < mem_basic_info.RegionSize; i++)
                    {
                        if (mem_basic_info.BaseAddress + i == 0x5a4d15f8)
                            Console.WriteLine("FIRST");
                        if (mem_basic_info.BaseAddress + i == 0x55cda890)
                            Console.WriteLine("FIRST");
                    }
                    proc_min_address_l += mem_basic_info.RegionSize;
                    proc_min_address = new IntPtr(proc_min_address_l);
                    continue;

                    int bytesLeft = mem_basic_info.RegionSize;
                    while (bytesLeft != 0)
                    {
                        if (bytesLeft > maxSize)
                        {
                            ReadProcessMemory(m_ProcessHandle, (IntPtr)mem_basic_info.BaseAddress, buffer, (uint)maxSize, out bytesRead);

                            for (int i = 0; i < maxSize - 3; i++)
                            {
                                int v = BitConverter.ToInt32(buffer, i);
                                if (v == value)
                                {
                                    memoryAddresses.Add((IntPtr)(mem_basic_info.BaseAddress + i));
                                }
                            }

                            mem_basic_info.BaseAddress += (maxSize - 3);
                            bytesLeft -= (maxSize - 3);
                        }
                        else
                        {
                            ReadProcessMemory(m_ProcessHandle, (IntPtr)mem_basic_info.BaseAddress, buffer, (uint)bytesLeft, out bytesRead);

                            for (int i = 0; i < bytesLeft - 3; i++)
                            {
                                int v = BitConverter.ToInt32(buffer, i);
                                if (v == value)
                                {
                                    memoryAddresses.Add((IntPtr)(mem_basic_info.BaseAddress + i));
                                }
                            }

                            mem_basic_info.BaseAddress += bytesLeft;
                            bytesLeft = 0;
                        }
                    }

                    //Console.WriteLine(mem_basic_info.BaseAddress + ", " + mem_basic_info.RegionSize);
                }

                // move to the next memory chunk
                proc_min_address_l += mem_basic_info.RegionSize;
                proc_min_address = new IntPtr(proc_min_address_l);
            }

            return true;
        }

        public bool NewScan(string text)
        {
            memoryAddresses.Clear();

            IntPtr bytesRead;
            uint PTR = 0x0;
            int size = 20480;
            uint endMem = 0x7fffffff;
            byte[] bytesFromText = Encoding.ASCII.GetBytes(text);
            byte[] buffer = new byte[size];
            int valueSize = bytesFromText.Length;

            while (PTR < endMem)
            {
                ReadProcessMemory(m_ProcessHandle, (IntPtr)PTR, buffer, (uint)buffer.Length, out bytesRead);

                for (int i = 0; i < buffer.Length - valueSize + 1; i++)
                {
                    if (buffer[i] == bytesFromText[0])
                    {
                        bool same = true;
                        for (int j = 0; j < valueSize; j++)
                        {
                            if (buffer[i + j] != bytesFromText[j])
                            {
                                same = false;
                                break;
                            }
                        }

                        if (same)
                        {
                            memoryAddresses.Add((IntPtr)(PTR + i));
                            textLength = valueSize;
                        }
                    }
                }

                PTR += (uint)(buffer.Length - valueSize + 1); // The last 3 bytes won't get read in the buffer. Therefore decrement with (valueSize + 1)
            }

            return true;
        }

        public bool NextScan(int value)
        {
            IntPtr bytesRead;
            byte[] buffer = new byte[sizeof(int)];
            List<IntPtr> addressesToRemove = new List<IntPtr>();

            foreach (IntPtr address in memoryAddresses)
            {
                ReadProcessMemory(m_ProcessHandle, address, buffer, (uint)buffer.Length, out bytesRead);

                int readValue = BitConverter.ToInt32(buffer, 0);
                if (readValue != value)
                {
                    addressesToRemove.Add(address);
                }
            }

            foreach (IntPtr address in addressesToRemove)
            {
                memoryAddresses.Remove(address);
            }

            return true;
        }

        public bool NewScanAt(long address)
        {
            address = 0x21dc8340;
            Console.WriteLine(address);
            memoryAddresses.Clear();
            memoryAddresses.Add((IntPtr)address);

            IntPtr bytesRead;
            byte[] buffer = new byte[sizeof(int)];

            ReadProcessMemory(m_ProcessHandle, (IntPtr)address, buffer, (uint)buffer.Length, out bytesRead);

            int readValue = BitConverter.ToInt32(buffer, 0);
            Console.WriteLine(readValue);

            return true;
        }

        public int GetCount()
        {
            return memoryAddresses.Count;
        }

        public void CloseHandle()
        {
            int returnValue;
            returnValue = CloseHandle(m_ProcessHandle);
            if (returnValue == 0)
                throw new Exception("Failed to close handle!");
        }
    }
}
