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
            if (args.Length == 0)
            {
                var key = StringToByteArray("2b7e151628aed2a6abf7158809cf4f3c");
                var msg = StringToByteArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");

                
                Console.WriteLine("cmac 'key' 'text'");
                Console.WriteLine("Example: ");
                Console.WriteLine("Key: 2b7e151628aed2a6abf7158809cf4f3c");
                Console.WriteLine("Text: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
                
                Console.Write("CMAC value:     ");
                PrintByteArr(AesCmac(key, msg));

                Console.WriteLine("Standard value: DF-A6-67-47-DE-9A-E6-30-30-CA-32-61-14-97-C8-27");
                Console.WriteLine("Reference: https://datatracker.ietf.org/doc/html/rfc4493#section-4");
            }
            else if (args.Length == 1)
            {
                Console.WriteLine("This program requires 2 parameters to run");
            }
            else
            {
                byte[] k    = StringToByteArray(args[0]);
                byte[] text = StringToByteArray(args[1]);
                
                Console.Write("СMAC value:     ");
                PrintByteArr(AesCmac(k, text));
            }
        }

        static byte[] AesCmac(byte[] key, byte[] msg)
        {
            bool flag;

            var encryptor = GetAlgorithm(key);
            
            GenerateSubkey(key, out var k1, out var k2, encryptor);
            
            var n = (msg.Length + 15) / bsize;

            if (n == 0)
            {
                n = 1;
                flag = false;
            }
            else
                flag = msg.Length % bsize == 0;

            if (flag)
                for (int i = 0; i < bsize; i++)
                    msg[msg.Length - bsize + i] ^= k1[i];
            
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

            for (int i = 0; i < n - 1; i++)
            {
                for (int j = 0; j < bsize; j++)
                    y[j] = (byte)(x[j] ^ msg[i * bsize + j]);
                
                x = SimpleEncryptV2(encryptor, y);
            }
            
            for (int j = 0; j < bsize; j++)
                y[j] = (byte)(x[j] ^ msg[msg.Length - bsize + j]);
            
            return SimpleEncryptV2(encryptor, y);
        }


        static void GenerateSubkey(byte[] key, out byte[] k1, out byte[] k2, ICryptoTransform encryptor)
        {
            var L = SimpleEncryptV2(encryptor, zero);
            
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

        static byte[] Rol(byte[] b)
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
        
        static ICryptoTransform GetAlgorithm(byte[] key)
        {
            return new AesManaged
            {
                Mode = CipherMode.CBC, 
                Padding = PaddingMode.Zeros, 
                Key = key, 
                IV = zero
            }.CreateEncryptor();
        }

        static byte[] SimpleEncryptV2(ICryptoTransform encryptor, byte[] bytes)
        {
            return encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
        }
        
        static void PrintByteArr(byte[] arr)
        {
            string hex = BitConverter.ToString(arr);
            Console.WriteLine(hex);
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }
    }
}