using System;
using System.IO;
using System.Linq;

namespace moon_princess_protection
{
    class Program
    {
        public enum DumpArgs
        {
            action,
            address,
            encryptedFilePath,
            codeOutputFilePath,
        }

        public enum WriteArgs
        {
            action,
            address,
            diskImageOutput,
            codeInputFilePath,
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine($"Cannot have 0 arguments.");
                Environment.Exit(1);
                return;
            }

            var action = args[0];

            switch (action)
            {
                case "Dump":
                    {
                        Console.WriteLine($"Dumping");

                        var requiredLength = (int)Enum.GetValues(typeof(DumpArgs)).Cast<DumpArgs>().Max() + 1;
                        if (args.Length != requiredLength)
                        {
                            Console.WriteLine($"Required argument number: {requiredLength}. Received: {args.Length}");
                            Environment.Exit(1);
                            break;
                        }

                        var compressedFilePath = args[(int)DumpArgs.encryptedFilePath];
                        var codeOutputFilePath = args[(int)DumpArgs.codeOutputFilePath];

                        Directory.SetCurrentDirectory(Path.GetDirectoryName(compressedFilePath));

                        var addresses = args[(int)DumpArgs.address].Split(",");

                        var decrypted = Encryption.Decrypt(compressedFilePath, addresses);
                        File.WriteAllBytes(codeOutputFilePath, decrypted.ToArray());
                    }
                    break;
                case "Write":
                    {
                        Console.WriteLine($"Writing");
                        var requiredLength = (int)Enum.GetValues(typeof(DumpArgs)).Cast<WriteArgs>().Max() + 1;
                        if (args.Length != requiredLength)
                        {
                            Console.WriteLine($"Required argument number: {requiredLength}. Received: {args.Length}");
                            Environment.Exit(1);
                            break;
                        }

                        var codeInputFilePath = args[(int)WriteArgs.codeInputFilePath];
                        var diskImageOutput = args[(int)WriteArgs.diskImageOutput];
                        var addresses = args[(int)WriteArgs.address].Split(",");

                        File.WriteAllBytes(diskImageOutput, Encryption.Encrypt(codeInputFilePath, diskImageOutput, addresses));
                    }
                    break;
                default:
                    Console.WriteLine($"Invalid first parameter: {action}");
                    Environment.Exit(1);
                    break;
            }

            Console.WriteLine($"Finished successfully.");
        }
    }
}
