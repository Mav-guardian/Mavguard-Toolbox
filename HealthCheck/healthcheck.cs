// === HealthCheck.cs ===
// Modular EDR Recon & Simulation Tool (Lab Use Only)
// Author: theMavguradian (2025)
// Description: A C# diagnostic utility to help understand what actions are flagged by EDRs

using System;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using System.ServiceProcess;

namespace HealthCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== HealthCheck Diagnostics ===\n");

            try
            {
                GetSystemInfo();
                ListServices();
                CheckSensitiveRegistryHives();
                ListScheduledTasks();
                CheckCurrentUserGroups();

                // === FUTURE MODULES: Uncomment to simulate riskier actions ===
                //SimulateDomainRecon();
                //SimulateRegistryWrite();
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex.Message);
            }

            Console.WriteLine("\n=== Diagnostics Complete ===");
        }

        static void GetSystemInfo()
        {
            Console.WriteLine("[+] Basic System Information:");
            Console.WriteLine("User: {0}", Environment.UserName);
            Console.WriteLine("Hostname: {0}", Environment.MachineName);
            Console.WriteLine("OS: {0}", Environment.OSVersion);
            Console.WriteLine("Architecture: {0}", Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit");
            Console.WriteLine("Uptime (s): {0}", Environment.TickCount / 1000);
            Console.WriteLine();
        }

        static void ListServices()
        {
            Console.WriteLine("[+] Services (non-Microsoft, non-running):");

            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController service in services)
            {
                if (!service.ServiceName.ToLowerInvariant().StartsWith("microsoft") &&
                    service.Status != ServiceControllerStatus.Running)
                {
                    Console.WriteLine("    {0} - {1} [{2}]", service.ServiceName, service.DisplayName, service.Status);
                }
            }
            Console.WriteLine();
        }

        static void CheckSensitiveRegistryHives()
        {
            Console.WriteLine("[+] Attempting to access sensitive registry hives (SAM/SECURITY)");

            string[] sensitiveKeys = new string[]
            {
                @"SECURITY\SAM",
                @"SECURITY\Policy\Secrets",
                @"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                @"SYSTEM\CurrentControlSet\Control\Lsa"
            };

            foreach (string subKey in sensitiveKeys)
            {
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey))
                    {
                        if (key != null)
                        {
                            Console.WriteLine("    [+] Successfully accessed HKLM\\{0}", subKey);
                        }
                        else
                        {
                            Console.WriteLine("    [-] HKLM\\{0} could not be opened or does not exist.", subKey);
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("    [!] Access denied to HKLM\\{0}", subKey);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("    [!] Error accessing HKLM\\{0}: {1}", subKey, ex.Message);
                }
            }
            Console.WriteLine();
        }

        static void ListScheduledTasks()
        {
            Console.WriteLine("[+] Scheduled Tasks (basic):");
            try
            {
                Process process = new Process();
                process.StartInfo.FileName = "schtasks.exe";
                process.StartInfo.Arguments = "/Query /FO LIST /V";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                string[] lines = output.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string line in lines)
                {
                    if (line.ToLowerInvariant().Contains("task name"))
                        Console.WriteLine("    {0}", line.Trim());
                }
            }
            catch
            {
                Console.WriteLine("    [!] Failed to query scheduled tasks.");
            }
            Console.WriteLine();
        }

        static void CheckCurrentUserGroups()
        {
            Console.WriteLine("[+] Current User Group Membership:");
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            foreach (IdentityReference group in identity.Groups)
            {
                try
                {
                    Console.WriteLine("    {0}", group.Translate(typeof(NTAccount)).ToString());
                }
                catch { }
            }
            Console.WriteLine();
        }

        // === FUTURE MODULES BELOW (Commented) ===

        // Simulates domain recon (requires domain membership)
        //static void SimulateDomainRecon()
        //{
        //    Console.WriteLine("[!] Simulating domain user listing (requires privileges)...");
        //    Process.Start("cmd.exe", "/c net user /domain");
        //}

        // Simulates privileged registry write
        //static void SimulateRegistryWrite()
        //{
        //    Console.WriteLine("[!] Attempting write to sensitive registry hive (RunAsPPL)...");
        //    try
        //    {
        //        using (RegistryKey lsa = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa", true))
        //        {
        //            lsa.SetValue("RunAsPPL", 1, RegistryValueKind.DWord);
        //            Console.WriteLine("    [+] Wrote to RunAsPPL (Simulation)");
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine("    [!] Registry write failed: {0}", ex.Message);
        //    }
        //    Console.WriteLine();
        //}
        // Simulate registry write (REQUIRES PRIVILEGE!)
                // using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\\RedFlagTest"))
                // {
                //     key.SetValue("MaliciousFlag", "TestWrite", RegistryValueKind.String);
                //     Console.WriteLine("[!] Simulated redflag: registry key written.");
                // }
        
    }
}
