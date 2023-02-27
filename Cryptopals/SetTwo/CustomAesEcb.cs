using System;
using System.Security.Cryptography;

namespace Cryptopals.SetTwo
{
	public static class CustomAesEbc
	{
		public static byte[] Decrypt(byte[] data, byte[] key)
		{
            Aes aes = Aes.Create();
            aes.Key = key;
            return aes.DecryptEcb(data, PaddingMode.None);
        }

        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            Aes aes = Aes.Create();
            aes.Key = key;

            return aes.EncryptEcb(data, PaddingMode.None);
        }
    }
}

