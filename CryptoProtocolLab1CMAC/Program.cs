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
            var msg = StringToByteArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
            // var msg = StringToByteArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
            
            // Console.Write("Key: ");
            // PrintByteArr(key);

            PrintByteArr(AesCmac(key, msg));
        }

        public static byte[] AesCmac(byte[] key, byte[] msg)
        {
            bool flag;

            GenerateSubkey(key, out var k1, out var k2);

            Console.Write("K1:  ");
            PrintByteArr(k1);
            Console.Write("K2:  ");
            PrintByteArr(k2);

            var n = (msg.Length + 15) / bsize;

            if (n == 0)
            {
                n = 1;
                flag = false;
            }
            else
                flag = msg.Length % bsize == 0;
            
            Console.WriteLine("N: " + n);
            
            Console.Write("MSG: ");
            PrintByteArr(msg);

            if (flag)
            {
                for (int i = 0; i < bsize; i++)
                    msg[msg.Length - bsize + i] ^= k1[i];
                Console.WriteLine();
            }
            else
            {
                var padding = new byte[16 - msg.Length % 16];
                padding[0] = 0x80;

                msg = msg.Concat(padding).ToArray();
                
                Console.Write("MSG2:");
                PrintByteArr(msg);

                for (int i = 0; i < bsize; i++)
                    msg[msg.Length - bsize + i] ^= k2[i];
            }
            
            Console.Write("MSG3:");
            PrintByteArr(msg);


            var x = zero;
            var y = zero;

            for (int i = 0; i < n - 1; i++)
            {
                for (int j = 0; j < bsize; j++)
                    y[j] = (byte)(x[j] ^ msg[i * bsize + j]);
                
                Console.Write("Y" + i + ":  ");
                PrintByteArr(y);
                
                x = AESEncrypt(key, y);
                
                Console.Write("X" + i + ":  ");
                PrintByteArr(x);
                Console.WriteLine();
            }
            
            for (int j = 0; j < bsize; j++)
                y[j] = (byte)(x[j] ^ msg[msg.Length - bsize + j]);
            
            Console.Write("Yl:  ");
            PrintByteArr(y);

            Console.WriteLine();
            return AESEncrypt(key, y);
        }


        public static void GenerateSubkey(byte[] key, out byte[] k1, out byte[] k2)
        {
            //var L = Encrypt(key, zero);
            var L = AESEncrypt(key, zero);
            
            Console.Write("L:  ");
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
            
            Console.Write("K1: ");
            PrintByteArr(k1);
            Console.Write("K2: ");
            PrintByteArr(k2);
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

        /*
        static byte[] Encrypt(byte[] key, byte[] data) {
            byte[] encrypted;  
            // Create a new AesManaged.    
            using(AesManaged aes = new AesManaged()) {  
                // Create encryptor    
                ICryptoTransform encryptor = aes.CreateEncryptor(key, zero);  
                // Create MemoryStream    
                using(MemoryStream ms = new MemoryStream()) {  
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using(CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {  
                        // Create StreamWriter and write data to a stream    
                        cs.Write(data, 0, data.Length);
                        encrypted = ms.ToArray();  
                    }  
                }  
            }  
            
            PrintByteArr(key);
            PrintByteArr(data);
            PrintByteArr(encrypted);
            Console.WriteLine();
            // Return encrypted data    
            return encrypted;  
        }
        */

        private static byte[] EncryptV2(byte[] data, byte[] key)
        {
            using (SymmetricAlgorithm crypt = Aes.Create())
            using (MemoryStream memoryStream = new MemoryStream())
            {
                crypt.Key = key;
                crypt.IV = zero;
                crypt.Mode = CipherMode.CBC;
                crypt.BlockSize = 128;

                using (CryptoStream cryptoStream = new CryptoStream(
                    memoryStream, crypt.CreateEncryptor(key, zero), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                }

                return memoryStream.ToArray();
            }
        }
        
        static byte[] Encrypt(string plainText, byte[] Key) {  
            byte[] encrypted;  
            // Create a new AesManaged.    
            using(AesManaged aes = new AesManaged()) {  
                // Create encryptor    
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, zero);  
                // Create MemoryStream    
                using(MemoryStream ms = new MemoryStream()) {  
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption    
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream    
                    // to encrypt    
                    using(CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {  
                        // Create StreamWriter and write data to a stream    
                        using(StreamWriter sw = new StreamWriter(cs))  
                            sw.Write(plainText);  
                        encrypted = ms.ToArray();  
                    }  
                }  
            }  
            // Return encrypted data    
            return encrypted;  
        }  
        
        static byte[] AESEncrypt(byte[] key, byte[] data)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(key, zero), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                    cs.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
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