using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptoProtocolLab1CMAC
{
    class Program
    {
        static byte[] zero = new byte[16];
        private static byte rb = 0x87;
        


        static void Main(string[] args)
        {
            var input = StringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");
            
            PrintByteArr(input);

            byte[] k1;
            byte[] k2;

            GenerateSubkey(input, out k1, out k2 );
            
        }

        public static void GenerateSubkey(byte[] key, out byte[] k1, out byte[] k2)
        {
            byte[] L;
            
            using (MemoryStream ms = new MemoryStream())
            {
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, zero), CryptoStreamMode.Write))
                {
                    cs.Write(zero, 0, zero.Length);
                    cs.FlushFinalBlock();

                    L = ms.ToArray();
                }
            }

            PrintByteArr(L);
            
            //bit shift over whole key
            k1 = Rol(L);
            
            //if most significant bit is zero
            if ((L[0] & 0x80) == 0x80)
                k1[15] ^= rb;
            
            //bit shift over whole key
            k2 = Rol(k1);
            
            //if most significant bit is zero
            if ((k1[0] & 0x80) == 0x80)
                k2[15] ^= rb;
        }
        
        public static byte[] Rol(byte[] b)
        {
            byte[] r = new byte[b.Length];
            byte carry = 0;

            for (int i = b.Length - 1; i >= 0; i--)
            {
                ushort u = (ushort)(b[i] << 1);
                r[i] = (byte)((u & 0xff) + carry);
                carry = (byte)((u & 0xff00) >> 8);
            }

            return r;
        }
        
        static void PrintByteArr(byte[] arr)
        {
            string hex = BitConverter.ToString(arr);
            Console.WriteLine(hex);
        }
        
        public static byte[] StringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}