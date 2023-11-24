using System;
using System.Diagnostics;
using System.Collections.Generic;

namespace Scanner
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] temp1 = { 0x01, 0x40, 0x00, 0x00 };

            Console.WriteLine(BitConverter.ToInt32(temp1, 0));

            Reader reader = new Reader();
            Process[] processes;

            while (true)
            {
                Console.Write("Process: ");
                string name = Console.ReadLine();
                processes = Process.GetProcessesByName(name);
                if (processes.Length == 0)
                {
                    Console.WriteLine("Couldn't find process!");
                }
                else
                {
                    Console.WriteLine(processes[0].MainWindowTitle);
                    break;
                }
            }

            while (true)
            {
                Console.Write("Command: ");
                string input = Console.ReadLine();

                if (input == "scanint")
                {
                    Console.Write("Value: ");
                    int val;
                    int.TryParse(Console.ReadLine(), out val);

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Searching...");
                    if (!reader.NewScan(val))
                    {
                        Console.WriteLine("Failed to scan!");
                        continue;
                    }

                    Console.WriteLine(reader.GetCount() + " different memory addresses found!");
                }
                else if (input == "scanfast")
                {
                    Console.Write("Value: ");
                    int val;
                    int.TryParse(Console.ReadLine(), out val);

                    reader.OpenProcessRead(processes[0]);

                    Console.WriteLine("Searching...");
                    if (!reader.FastScan(val))
                    {
                        Console.WriteLine("Failed to scan!");
                        continue;
                    }

                    Console.WriteLine(reader.GetCount() + " different memory addresses found!");
                }
                else if (input == "scanstring")
                {
                    Console.Write("Text: ");
                    string text = Console.ReadLine();

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Searching...");
                    if (!reader.NewScan(text))
                    {
                        Console.WriteLine("Failed to scan!");
                        continue;
                    }

                    Console.WriteLine(reader.GetCount() + " different memory addresses found!");
                }
                else if (input == "next")
                {
                    Console.Write("Value: ");
                    int val;
                    int.TryParse(Console.ReadLine(), out val);

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Searching...");
                    if (!reader.NextScan(val))
                    {
                        Console.WriteLine("Failed to scan!");
                        continue;
                    }

                    Console.WriteLine(reader.GetCount() + " different memory addresses found!");
                }
                else if (input == "writeint")
                {
                    Console.Write("Value: ");
                    int val;
                    int.TryParse(Console.ReadLine(), out val);

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Writing...");
                    reader.WriteInt(val);

                    Console.WriteLine("Done!");
                }
                else if (input == "writestring")
                {
                    Console.Write("Text: ");
                    string text = Console.ReadLine();

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Writing...");
                    reader.WriteString(text);

                    Console.WriteLine("Done!");
                }
                else if (input == "scanat")
                {
                    Console.Write("Address: ");
                    long val;
                    long.TryParse(Console.ReadLine(), out val);

                    reader.OpenProcess(processes[0]);

                    Console.WriteLine("Searching...");
                    if (!reader.NewScanAt(val))
                    {
                        Console.WriteLine("Failed to scan!");
                        continue;
                    }

                    //Console.WriteLine(reader.GetCount() + " different memory addresses found!");
                }

                reader.CloseHandle();
            }
        }
    }
}
