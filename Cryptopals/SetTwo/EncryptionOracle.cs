using System;
namespace Cryptopals.SetTwo
{
	public class EncryptionOracle
	{
        private static readonly byte[] staticKey = new byte[] {
            0xDE, 0xAD, 0xBE, 0xEF,
            0xFA, 0xCE, 0xB0, 0x0C,
            0x12, 0x34, 0x56, 0x78,
            0xF0, 0xD2, 0xB4, 0x96,
        };

        private static readonly byte[] secretData = Convert.FromBase64String(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
            "YnkK"
            );

        public EncryptionOracle() { }

        public static byte[] Aes128EcbEncrypt(byte[] data)
        {
            byte[] plaintext = new byte[data.Length + secretData.Length];
            data.CopyTo(plaintext, 0);
            secretData.CopyTo(plaintext, data.Length);

            return CustomAesEbc.Encrypt(Crypto.PadBlock(plaintext, 16), staticKey);
        }
	}
}

