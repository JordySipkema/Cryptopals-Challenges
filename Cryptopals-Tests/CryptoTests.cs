using System;
using System.Text;
using FluentAssertions;
using Cryptopals.SetTwo;
using Cryptopals.SetOne;

namespace Cryptopals_Tests
{
	[TestClass]
    public class CryptoTests
	{
        public CryptoTests() { }

		[TestMethod]
		public void Test_09_ImplementPkcs7Padding_A()
		{
			byte[] input = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
			byte[] expected = Encoding.UTF8.GetBytes("YELLOW SUBMARINE\x04\x04\x04\x04");

			byte[] result = Crypto.PadBlock(input, 20);

			result.Should().BeEquivalentTo(expected);
        }

        [TestMethod]
        public void Test_09_ImplementPkcs7Padding_B()
        {
            byte[] input = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            byte[] expected = Encoding.UTF8.GetBytes("YELLOW SUBMARINE\x02\x02");

            byte[] result = Crypto.PadBlock(input, 18);

            result.Should().BeEquivalentTo(expected);
        }

        [TestMethod]
        public void Test_09_ImplementPkcs7Padding_C()
        {
            byte[] input = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            byte[] expected = Encoding.UTF8.GetBytes("YELLOW SUBMARINE\x04\x04\x04\x04");

            byte[] result = Crypto.PadBlock(input, 10);

            result.Should().BeEquivalentTo(expected);
        }

        // Just testing that the custom AesEcb impl still works after refactoring.
        [TestMethod]
        public void Test_10a_AesEbcDecrypt()
        {
            // Arrange
            string inputB64 = File.ReadAllText("./7.txt");
            byte[] input = Convert.FromBase64String(inputB64);
            byte[] key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");

            // Act
            byte[] decrypted = CustomAesEbc.Decrypt(input, key);

            // Assert
            BruteforceResult result = new() { Decoded = decrypted, Key = key };
            result.DecodedStr.Should().StartWithEquivalentOf("I'm back and I'm ringin' the bell");
        }

        [TestMethod]
        public void Test_10b_AesCbcDecrypt()
        {
            // Arrange
            string inputB64 = File.ReadAllText("./10.txt");
            byte[] input = Convert.FromBase64String(inputB64);
            byte[] key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            byte[] iv = new byte[16];

            // Act
            byte[] decrypted = CustomAesCbc.Decrypt(input, iv, key);

            // Assert
            BruteforceResult result = new() { Decoded = decrypted, Key = key };
            result.DecodedStr.Should().StartWithEquivalentOf("I'm back and I'm ringin' the bell");
        }

        [TestMethod]
        public void Test_10c_AesCbcEncrypt()
        {
            // Arrange
            string inputB64 = File.ReadAllText("./10-test.txt");
            byte[] input = Convert.FromBase64String(inputB64);
            byte[] key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            byte[] iv = new byte[16];

            // Act
            byte[] encrypted = CustomAesCbc.Encrypt(input, iv, key);
            byte[] decrypted = CustomAesCbc.Decrypt(encrypted, iv, key);

            // Assert
            BruteforceResult result = new() { Decoded = decrypted, Key = key };
            result.DecodedStr.Should().BeEquivalentTo(Encoding.UTF8.GetString(input));
        }

        [TestMethod]
        public void Test_11_DetectRandomCrypto()
        {
            string inputB64 = File.ReadAllText("./10-test.txt");
            byte[] input = Convert.FromBase64String(inputB64);

            for (int it = 0; it < 10; it++)
            {
                RandomCryptoGenerator rcg = new RandomCryptoGenerator();
                RandomCrypto rc = rcg.GetRandomCrypto(input);

                bool isEcb = hasRepeatingPatterns(rc.Ciphertext);

                CipherMode expected = isEcb ? CipherMode.ECB : CipherMode.CBC;

                rc.CipherMode.Should().Be(expected);
            }
        }

        private bool hasRepeatingPatterns(byte[] input, int chunkSize = 16)
        {
            var chunks = input.Chunk(chunkSize);
            List<byte[]> seen = new();

            foreach (byte[] chunk in chunks)
            {
                if (seen.Any(x => x.SequenceEqual(chunk)))
                    return true;

                seen.Add(chunk);
            }
            return false;
        }
    }
}

