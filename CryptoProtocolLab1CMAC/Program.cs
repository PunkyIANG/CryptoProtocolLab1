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
        private static byte[] rb = new byte[16];
        
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


        static void Main(string[] args)
        {
            rb[0] = 0x87;

            var input = StringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");
            
            PrintByteArr(input);

            byte[] k1;
            byte[] k2;

            GenerateSubkey(input, out k1, out k2 );

            //Console.WriteLine("Hello World!");
        }

        public static void GenerateSubkey(byte[] k, out byte[] k1, out byte[] k2)
        {
            var aes = Aes.Create();
            byte[] L;
            k1 = new byte[16];
            k2 = new byte[16];
            var IV = new byte[16];

            aes.Key = k;
            aes.IV = IV;
            
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(zero);
                    }
                    L = msEncrypt.ToArray();
                }
            }
            
            PrintByteArr(L);
            
            //bit shift over whole key
            var temp = new BitArray(L);
            for (int i = 0; i < temp.Length - 1; i++)
                temp[i] = temp[i + 1];
            
            temp.CopyTo(k1, 0);

            //if most significant bit is zero
            if ((L[^1] & 128) == 0)
            {
                for (int i = 0; i < k1.Length; i++)
                {
                    k1[i] ^= rb[i];
                }
            }
            
            //bit shift over whole key
            var temp2 = new BitArray(k1);
            for (int i = 0; i < temp2.Length - 1; i++)
                temp2[i] = temp2[i + 1];
            
            temp2.CopyTo(k2, 0);

            //if most significant bit is zero
            if ((L[^1] & 128) == 0)
            {
                for (int i = 0; i < k2.Length; i++)
                {
                    k2[i] ^= rb[i];
                }
            }
            
            PrintByteArr(k1);
            PrintByteArr(k2);
        }
    }
}