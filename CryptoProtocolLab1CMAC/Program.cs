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

        const byte rb = 0x87;
        const byte bsize = 16;


        static void Main(string[] args)
        {
            var key = StringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");

            PrintByteArr(key);

            byte[] k1, k2;

            GenerateSubkey(key, out k1, out k2);
            
            PrintByteArr(k1);
            PrintByteArr(k2);
            
            PrintByteArr(AesCmac(key, new byte[0]));
        }

        public static byte[] AesCmac(byte[] key, byte[] msg)
        {
            byte[] k1, k2;
            bool flag;

            GenerateSubkey(key, out k1, out k2);

            var n = (int) Math.Ceiling((float) msg.Length / bsize);

            if (n == 0)
            {
                n = 1;
                flag = false;
            }
            else
                flag = msg.Length % bsize == 0;

            if (flag)
            {
                for (int i = 0; i < bsize; i++)
                    msg[msg.Length - bsize + i] ^= k1[i];
            }
            else
            {
                var padding = new byte[16 - msg.Length % 16];
                padding[0] = 0x80;

                msg = msg.Concat(padding).ToArray();

                for (int i = 0; i < bsize; i++)
                    msg[msg.Length - bsize + i] ^= k2[i];
            }
            
            var x = zero;
            var y = zero;

            for (int i = 0; i < n-1; i++)
            {
                for (int j = 0; j < bsize; j++)
                    y[j] = (byte)(x[j] ^ msg[i * bsize + j]);
                
                x = AesEncrypt(key, y);
            }
            
            for (int j = 0; j < bsize; j++)
                y[j] = (byte)(x[j] ^ msg[msg.Length - bsize + j]);

            return AesEncrypt(key, y);
        }


        public static void GenerateSubkey(byte[] key, out byte[] k1, out byte[] k2)
        {
            var L = AesEncrypt(key, zero);
            
            // PrintByteArr(L);

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
                ushort u = (ushort) (b[i] << 1);
                r[i] = (byte) ((u & 0xff) + carry);
                carry = (byte) ((u & 0xff00) >> 8);
            }

            return r;
        }

        public static byte[] AesEncrypt(byte[] key, byte[] data)
        {
            var ms = new MemoryStream();
            var aes = new AesCryptoServiceProvider();

            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            var cs = new CryptoStream(ms, aes.CreateEncryptor(key, zero), CryptoStreamMode.Write);
            cs.Write(data, 0, zero.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        static void PrintByteArr(byte[] arr)
        {
            string hex = BitConverter.ToString(arr);
            Console.WriteLine(hex);
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}