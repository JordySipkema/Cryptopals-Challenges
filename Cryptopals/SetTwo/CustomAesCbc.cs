using System;
namespace Cryptopals.SetTwo
{
    public class CustomAesCbc
    {
        public CustomAesCbc()
        {
        }

        public static byte[] Decrypt(byte[] ciphertext, byte[] iv, byte[] key)
        {
            IEnumerable<byte[]> chunks = ciphertext.Chunk(16);

            byte[] result = new byte[ciphertext.Length];
            for (int idx = 0; idx < chunks.Count(); idx++)
            {
                byte[] block = chunks.ElementAt(idx);
                byte[] decrypted = CustomAesEbc.Decrypt(block, key);
                byte[] plaintext = Crypto.XOR(decrypted, iv);

                plaintext.CopyTo(result, idx * 16);

                iv = block;
            }

            return Crypto.UnpadBlock(result);
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] iv, byte[] key)
        {
            byte[] paddedPlaintext = Crypto.PadBlock(plaintext, 16);
            IEnumerable<byte[]> chunks = paddedPlaintext.Chunk(16);

            byte[] result = new byte[paddedPlaintext.Length];
            for (int idx = 0; idx < chunks.Count(); idx++)
            {
                byte[] block = chunks.ElementAt(idx);
                byte[] xored = Crypto.XOR(block, iv);
                byte[] ciphertext = CustomAesEbc.Encrypt(xored, key);

                ciphertext.CopyTo(result, idx * 16);

                iv = ciphertext;
            }

            return result;
        }

        //  In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

        // The first plaintext block, which has no associated previous ciphertext block,
        // is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

        // Implement CBC mode by hand by taking the ECB function you wrote earlier,
        // making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
        // and using your XOR function from the previous exercise to combine them.
    }
}

