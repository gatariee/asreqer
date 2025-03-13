using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Diagnostics;
using System.Net.NetworkInformation; 
using System.Linq;

namespace sniffer
{
    class Program
    {
        private const int SIO_RCVALL = unchecked((int)0x98000001);

        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: sniffer <interfaceName> <runForSeconds> <outputFile>");
                Console.WriteLine("Example: sniffer \"Ethernet\" 10 capture.pcap");
                return;
            }

            string interfaceName = args[0];
            int runSeconds = int.Parse(args[1]);
            string outputFile = args[2];

            var allInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            var selectedInterface = allInterfaces
                .FirstOrDefault(ni => ni.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));

            if (selectedInterface == null)
            {
                Console.WriteLine($"Error: No interface found with name '{interfaceName}'.");
                PrintInterfaces(allInterfaces);
                return;
            }

            var ipProps = selectedInterface.GetIPProperties();
            var unicast = ipProps.UnicastAddresses
                .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork);

            if (unicast == null)
            {
                Console.WriteLine($"Error: Interface '{interfaceName}' has no IPv4 address.");
                return;
            }

            IPAddress ipAddress = unicast.Address;
            Console.WriteLine($"[+] Using interface '{selectedInterface.Name}' with IP {ipAddress}");

            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            try
            {
                socket.Bind(new IPEndPoint(ipAddress, 0));

                byte[] inValue = BitConverter.GetBytes(1);
                byte[] outValue = new byte[4];
                socket.IOControl(SIO_RCVALL, inValue, outValue);

                socket.ReceiveBufferSize = 65535;
                socket.Blocking = false; // don't block other threads

                Console.WriteLine($"[+] Capturing for {runSeconds} seconds...");

                using (FileStream fs = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
                {
                    WritePcapGlobalHeader(fs);

                    Stopwatch sw = Stopwatch.StartNew();
                    byte[] buffer = new byte[65535];

                    while (sw.Elapsed.TotalSeconds < runSeconds)
                    {
                        try
                        {
                            int received = socket.Receive(buffer);
                            if (received > 0)
                            {
                                WritePcapPacketRecord(fs, buffer, received);
                            }
                        }
                        catch (SocketException se)
                        {
                            if (se.ErrorCode != 10035)
                            {
                                Console.WriteLine($"Socket exception: {se.Message}");
                                break;
                            }
                        }
                    }
                }

                Console.WriteLine("[+] Capture complete!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            finally
            {
                if (socket.Connected)
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                socket.Close();
            }
        }

        private static void WritePcapGlobalHeader(Stream stream)
        {
            byte[] magicNumber = { 0xd4, 0xc3, 0xb2, 0xa1 };
            byte[] versionMajor = BitConverter.GetBytes((ushort)2);
            byte[] versionMinor = BitConverter.GetBytes((ushort)4);
            byte[] thisZone = BitConverter.GetBytes((int)0);
            byte[] sigFigs = BitConverter.GetBytes((int)0);
            byte[] snapLen = BitConverter.GetBytes((int)65535);
            byte[] linkType = BitConverter.GetBytes((int)101);
            stream.Write(magicNumber, 0, magicNumber.Length);
            stream.Write(versionMajor, 0, versionMajor.Length);
            stream.Write(versionMinor, 0, versionMinor.Length);
            stream.Write(thisZone, 0, thisZone.Length);
            stream.Write(sigFigs, 0, sigFigs.Length);
            stream.Write(snapLen, 0, snapLen.Length);
            stream.Write(linkType, 0, linkType.Length);
        }

        private static void WritePcapPacketRecord(Stream stream, byte[] packetData, int length)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            uint seconds = (uint)(now / 1000);
            uint microseconds = (uint)((now % 1000) * 1000);

            byte[] tsSec = BitConverter.GetBytes(seconds);
            byte[] tsUsec = BitConverter.GetBytes(microseconds);

            byte[] inclLen = BitConverter.GetBytes(length);
            byte[] origLen = BitConverter.GetBytes(length);

            stream.Write(tsSec, 0, tsSec.Length);
            stream.Write(tsUsec, 0, tsUsec.Length);
            stream.Write(inclLen, 0, inclLen.Length);
            stream.Write(origLen, 0, origLen.Length);

            stream.Write(packetData, 0, length);
        }

        private static void PrintInterfaces(NetworkInterface[] interfaces)
        {
            Console.WriteLine("Available interfaces:");
            foreach (var ni in interfaces)
            {
                Console.WriteLine($" - {ni.Name} ({ni.NetworkInterfaceType})");
                var ips = ni.GetIPProperties()?.UnicastAddresses;
                if (ips != null)
                {
                    foreach (var ip in ips)
                    {
                        Console.WriteLine($"     IP: {ip.Address}");
                    }
                }
            }
        }
    }
}
