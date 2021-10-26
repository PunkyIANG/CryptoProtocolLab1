using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoProtocolLab1HMAC
{
    class Program
    {
        const int k0Length = 64;
        const int hashLength = 32;
        const byte ipad = 0x36;
        const byte opad = 0x5c;

        static void PrintByteArr(byte[] arr)
        {
            string hex = BitConverter.ToString(arr);
            Console.WriteLine(hex);
        }

        static void Main(string[] args)
        {
            switch (args.Length)
            {
                case 0:
                {
                    byte[] k    = Encoding.ASCII.GetBytes("key");
                    byte[] text = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");

                    HMACSHA256 hmac = new HMACSHA256(k);
                
                    Console.WriteLine("hmac 'key' 'text'");
                    Console.WriteLine("This program uses SHA-256 as its hashing algorithm");
                    Console.WriteLine("Example: ");
                    Console.WriteLine("Key: key");
                    Console.WriteLine("Text: The quick brown fox jumps over the lazy dog");
                    Console.Write("HMAC value:     ");
                    PrintByteArr(HMACStuff(k, text));

                    Console.Write("Standard value: ");
                    PrintByteArr(hmac.ComputeHash(text));

                    var temp = Console.ReadKey();

                    break;
                }
                case 1:
                    Console.WriteLine("This program requires 2 parameters to run");
                    break;
                default:
                {
                    byte[] k    = Encoding.ASCII.GetBytes(args[0]);
                    byte[] text = Encoding.ASCII.GetBytes(args[1]);

                    HMACSHA256 hmac = new HMACSHA256(k);

                    Console.Write("HMAC value:     ");
                    PrintByteArr(HMACStuff(k, text));

                    Console.Write("Standard value: ");
                    PrintByteArr(hmac.ComputeHash(text));
                    break;
                }
            }
        }

        static byte[] HMACStuff(byte[] k, byte[] text)
        {
            HashAlgorithm sha = SHA256.Create();
            
            byte[] k0;
            if (k.Length == k0Length)
            {
                k0 = k;
            } 
            else if (k.Length > k0Length)
            {
                k0 = new byte[k0Length];
                Array.Copy(sha.ComputeHash(k), k0, hashLength);
            } 
            else
            {
                k0 = new byte[k0Length];
                Array.Copy(k, k0, k.Length);
            }
            
            byte[] IKeyPad = new byte[k0Length + text.Length];

            for (int i = 0; i < k0Length; i++)
                IKeyPad[i] = (byte)(k0[i] ^ ipad);

            Array.Copy(text, 0, IKeyPad, k0Length, text.Length);

            var V = sha.ComputeHash(IKeyPad);
            
            byte[] OKeyPad = new byte[k0Length + hashLength];

            for (int i = 0; i < k0Length; i++)
                OKeyPad[i] = (byte)(k0[i] ^ opad);

            Array.Copy(V, 0, OKeyPad, k0Length, hashLength);
            
            return sha.ComputeHash(OKeyPad);
        }
    }
}
