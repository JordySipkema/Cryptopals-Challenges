using Cryptopals.Exceptions;
using Cryptopals.Helpers;

namespace Cryptopals.SetTwo {
    public class AesEcbDecryptor {

        public delegate byte[] CryptoFunction(byte[] data);
        private readonly Crypto.CryptoFunction cryptoFunction;
        private readonly int blocksize;

        public AesEcbDecryptor(Crypto.CryptoFunction cryptoFunction) {
            this.cryptoFunction = cryptoFunction;
            this.blocksize = Crypto.DetectBlocksize(cryptoFunction);
        }

        /// <summary>
        /// Byte at a time decryption (Exercise 12)
        /// </summary>
        /// <returns>The decrypted string</returns>
        public byte[] Decrypt() {
            // TODO: Optimize by paralellization.
            // Chunk in blocks equal to blocksize, decrypt them at the same time.
            int bytesToDecrypt = cryptoFunction(Array.Empty<byte>()).Length;
            byte[] decrypted = DecryptByteAtATime(Array.Empty<byte>(), bytesToDecrypt);

            return Crypto.UnpadBlock(decrypted);
        }

        private byte[] DecryptByteAtATime(byte[] knownBytes, int bytesToDecrypt) {
            if (knownBytes.Length == bytesToDecrypt)
                return knownBytes;

            byte[] padding = Crypto.PadBlockInFront(knownBytes, blocksize);
            byte[] nullPadding = padding.Take(padding.Length - knownBytes.Length - 1).ToArray();

            Dictionary<string, byte> lookup = Enumerable.Range(0, 256)
                .Select(i => (byte) i)
                .ToDictionary(key => GetTruncatedCiphertext(key, padding), key => key);

            byte[] ciphertext = cryptoFunction(nullPadding);
            string subset = Convert.ToHexString(ciphertext.Take(padding.Length).ToArray());

            bool lookupResult = lookup.TryGetValue(subset, out byte value);

            if (!lookupResult)
                // Are we done decrypting? (We cant decrypt padding)
                if (knownBytes.LastOrDefault() == 0x01) // Somehow I always end up with 0x01 as last value.
                    return knownBytes;
                else
                    throw new DecryptionException("Failed to decrypt! Byte not found in range 0x00-0xFF");

            return DecryptByteAtATime(ByteArray.Concat(knownBytes, value), bytesToDecrypt);
        }

        private static string GetTruncatedCiphertext(byte key, byte[] padding) {
            byte[] concat = ByteArray.Concat(padding.Skip(1).ToArray(), key);
            byte[] ciphertext = EncryptionOracle.Aes128EcbEncrypt(concat);
            byte[] truncated = ciphertext.Take(padding.Length).ToArray();

            return Convert.ToHexString(truncated);
        }
    }
}
