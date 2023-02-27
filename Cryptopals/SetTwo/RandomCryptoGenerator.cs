using System;
namespace Cryptopals.SetTwo
{
    public class RandomCryptoGenerator
    {
        private byte[] staticKey = new byte[] {
            0xDE, 0xAD, 0xBE, 0xEF,
            0xFA, 0xCE, 0xB0, 0x0C,
            0x12, 0x34, 0x56, 0x78,
            0xF0, 0xD2, 0xB4, 0x96,
        };

        private Random random = new Random();

        public RandomCryptoGenerator()
        {
        }

        public RandomCrypto GetRandomCrypto(byte[] data)
        {
            byte[] key = GetRandomBytes(16);
            byte[] prefix = GetRandomBytes(random.Next(5, 11));
            byte[] postfix = GetRandomBytes(random.Next(5, 11));
            byte[] plaintext = prefix.Concat(data).Concat(postfix).ToArray();

            switch (GetCipherMode())
            {
                case CipherMode.ECB:
                    return new RandomCrypto()
                    {
                        CipherMode = CipherMode.ECB,
                        Ciphertext = CustomAesEbc.Encrypt(Crypto.PadBlock(plaintext, 16), key),
                    };
                case CipherMode.CBC:
                    byte[] iv = GetRandomBytes(16);
                    return new RandomCrypto()
                    {
                        CipherMode = CipherMode.CBC,
                        Ciphertext = CustomAesCbc.Encrypt(plaintext, iv, key),
                    };
                default:
                    throw new ArgumentException("Unknown CipherMode");
            }
        }

        private byte[] GetRandomBytes(int count)
        {
            byte[] result = new byte[count];
            random.NextBytes(result);

            return result;
        }

        private CipherMode GetCipherMode()
        {
            if (random.Next(2) == 0)
                return CipherMode.ECB;
            else
                return CipherMode.CBC;
        }
    }

    public enum CipherMode
    {
        Unknown,
        ECB,
        CBC
    }

    public class RandomCrypto
    {
        public CipherMode CipherMode { get; set; } = CipherMode.Unknown;
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
    }
}
