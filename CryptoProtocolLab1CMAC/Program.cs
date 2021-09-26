using System;
using System.Collections;
using System.IO;
using System.Security.Cryptography;

namespace CryptoProtocolLab1CMAC
{
    class Program
    {
        static byte[] zero = new byte[16];
        private static byte[] rb = new byte[16];

        static void Main(string[] args)
        {
            rb[0] = 0x87;
            
            
            Console.WriteLine("Hello World!");
        }

        public void GenerateSubkey(byte[] k, out byte[] k1, out byte[] k2)
        {
            var aes = Aes.Create();
            byte[] L;
            k1 = new byte[16];
            k2 = new byte[16];

            aes.Key = k;
            
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
        }
    }
}