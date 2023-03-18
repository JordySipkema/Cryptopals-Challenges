using System;
using System.Text;
using FluentAssertions;
using Cryptopals.SetTwo;
using Cryptopals.SetOne;
using Microsoft.VisualStudio.TestPlatform.ObjectModel;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Drawing;

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
            string inputB64 = File.ReadAllText("./Input/07.txt");
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
            string inputB64 = File.ReadAllText("./Input/10.txt");
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
            string inputB64 = File.ReadAllText("./Input/10-test.txt");
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
            byte[] input = new byte[256];

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

        [TestMethod]
        public void Test_12_EcbDecryptionSimple()
        {
            string inputB64 = File.ReadAllText("./Input/10.txt");
            byte[] input = Convert.FromBase64String(inputB64);

            //EncryptionOracle.Aes128EcbEncrypt();
        }

        [TestMethod]
        public void Test_12_DetectBlocksize()
        {
            Crypto.DetectBlocksize(EncryptionOracle.Aes128EcbEncrypt).Should().Be(16);
        }


        //Feed identical bytes of your-string to the function 1 at a time
        //--- start with 1 byte ("A"), then "AA", then "AAA" and so on.
        //Discover the block size of the cipher.You know it, but do this step anyway.

        //Detect that the function is using ECB. You already know, but do this step anyways.

        //Knowing the block size, craft an input block that is exactly 1 byte short
        //(for instance, if the block size is 8 bytes, make "AAAAAAA").
        //Think about what the oracle function is going to put in that last byte position.

        //Make a dictionary of every possible last byte by feeding different strings to the oracle;
        //for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.

        //Match the output of the one-byte-short input to one of the entries in your dictionary.
        //You've now discovered the first byte of unknown-string.

        //Repeat for the next byte.

    }
}

