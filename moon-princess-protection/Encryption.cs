using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace moon_princess_protection
{
    public static class Encryption
    {
        private static readonly byte[]
            key1 = new byte[] { 0x0C, 0xC9, 0xAF, 0xD3, 0xF8, 0x3A, 0x0E, 0xEF, 0xE6, 0xFE, 0x32, 0x0E, 0xEF },
            key2 = new byte[] { 0x4A, 0xD7, 0x3B, 0x78, 0x02, 0x6E, 0x84, 0x7B, 0xFE, 0xC1, 0x2F };

        private static readonly int key1Start = key1.Length - 1;
        private static readonly int key2Start = key2.Length - 1;

        // Exists to add entropy
        const int bStart = 0xb;
        const int cStart = 0xd;

        const int bankSize = 0x100;

        public static List<byte> Decrypt(string s, string[] rawAddresses)
        {
            var diskImage = File.ReadAllBytes(s);

            var encrypted = Array.Empty<byte>();

            foreach (var a in rawAddresses)
            {
                ParseArgument(a, out int address, out int bankCount);

                for (int i = 0; i < bankCount; i++)
                {
                    var chunk = diskImage.Skip(address + i * bankSize).Take(bankSize).ToArray();
                    encrypted = encrypted.Concat(chunk).ToArray();
                }
            }

            var decrypted = new List<byte>();

            for (int i = 0, c = bStart, b = cStart, key1I = key1Start, key2I = key2Start; i < encrypted.Length; i++, c--, b--, key1I--, key2I--)
            {
                var aaa = new byte[encrypted.Length - i];
                Array.Copy(encrypted, i, aaa, 0, aaa.Length);

                if (aaa.All(o => o == 0x0))
                {
                    decrypted = decrypted.Concat(aaa).ToArray().ToList();
                    break;
                }

                key1I = key1I == -1 ? key1Start : key1I;
                key2I = key2I == -1 ? key2Start : key2I;

                c = c == 0 ? bStart : c;
                b = b == 0 ? cStart : b;

                /*
                First operation before pushed to stack
                AD2A: 1A          ld   a,(de)
                AD2B: 91          sub  c
                AD2C: AE          xor  (hl)
                AD2D: F5          push af
                */
                byte temp = (byte)((encrypted[i] - c) ^ key1[key1I]);

                /*
                Second operation after being pulled from stack
                AD38: F1          pop  af
                AD39: AE          xor  (hl)
                AD3A: 80          add  a,b
                AD3B: 12          ld   (de),a
                */
                temp = (byte)((temp ^ key2[key2I]) + b);

                decrypted.Add(temp);
            }

            return decrypted;
        }

        public static byte[] Encrypt(string codeInputFilePath, string diskImageOutput, string[] rawAddresses)
        {
            var diskImage = File.ReadAllBytes(diskImageOutput);
            var decrypted = File.ReadAllBytes(codeInputFilePath);
            var encrypted = new List<byte>();

            for (int i = 0, c = bStart, b = cStart, key1I = key1Start, key2I = key2Start; i < decrypted.Length; i++, c--, b--, key1I--, key2I--)
            {
                key1I = key1I == -1 ? key1Start : key1I;
                key2I = key2I == -1 ? key2Start : key2I;

                c = c == 0 ? bStart : c;
                b = b == 0 ? cStart : b;

                byte temp = (byte)((decrypted[i] - b) ^ key2[key2I]);
                temp = (byte)((temp ^ key1[key1I]) + c);

                encrypted.Add(temp);
            }

            var cursor = 0;
            foreach (var a in rawAddresses)
            {
                ParseArgument(a, out int address, out int bankCount);

                var regionSize = bankCount * bankSize;
                var chunk = encrypted.Skip(cursor).Take(regionSize).ToArray();
                Array.Copy(chunk, 0, diskImage, address, chunk.Length);
                cursor += regionSize;
            }

            return diskImage;
        }

        private static void ParseArgument(string arg, out int address, out int bankCount)
        {
            var a = arg.Split("*");
            if (a.Length != 2)
            {
                throw new Exception($"Argument malformed: \"{arg}\"");
            }

            address = MyMath.HexToDec(a[0]);
            bankCount = int.Parse(a[1]);
        }
    }
}
