using System;
using System.Text;
using FluentAssertions;
using Cryptopals.SetTwo;
using Cryptopals.SetOne;
using Cryptopals.Helpers;

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
        public void Test_12_DetectBlocksize()
        {
            Crypto.DetectBlocksize(EncryptionOracle.Aes128EcbEncrypt).Should().Be(16);
        }

        [TestMethod]
        public void Test_12_PadBlockInFront() {
            byte[] input = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            byte[] expected = Encoding.UTF8.GetBytes("\x00\x00\x00\x00YELLOW SUBMARINE");

            byte[] result = Crypto.PadBlockInFront(input, 20);

            result.Should().BeEquivalentTo(expected);
        }

        [TestMethod]
        public void Test_12_EcbDecryptionSimple() {
            string inputB64 = File.ReadAllText("./Input/12.txt");
            byte[] input = Convert.FromBase64String(inputB64);
                      
            var underTest = new AesEcbDecryptor(EncryptionOracle.Aes128EcbEncrypt);
            var plaintext = underTest.Decrypt();

            var result = Encoding.UTF8.GetString(plaintext);

            plaintext.Should().BeEquivalentTo(input);
        }

        [TestMethod]
        public void Test_13_EcbCutAndPaste()
        {
            /* 
             * email=foo@foobar     Keep (1)
             * admin***********     This should become the last block (3)
             * .nl&uid=10&role=     Keep (2)
             * user                 Discard
             * 
             * *** = PCKS7 padding
             */

            // Setup:
            byte[] admin = Crypto.PadBlock(Encoding.UTF8.GetBytes("admin"), 16);
            string rogueEmail = "foo@foobar" +
                Encoding.UTF8.GetString(admin) +
                ".nl";

            byte[] cookie = Cookie.GetProfileFor(rogueEmail);

            // Extract parts of the rogue cookie
            byte[] emailPart = cookie.Take(16).ToArray();
            byte[] adminPart = cookie.Skip(16).Take(16).ToArray();
            byte[] uidPart = cookie.Skip(32).Take(16).ToArray();

            // Construct the new cookie
            byte[] newCookie = ByteArray.Concat(emailPart, uidPart, adminPart);
            Cookie rogueCookie = Cookie.AuthenticateUser(newCookie);

            rogueCookie.IsAdmin().Should().Be(true);
            rogueCookie.GetString().Should().Be("email=foo@foobar.nl&uid=10&role=admin");
        }

        // TODO: 14

        [TestMethod]
        public void Test_15_PCKS7_Padding_Validation_Succes()
        {
            byte[] input = Encoding.UTF8.GetBytes("ICE ICE BABY\x04\x04\x04\x04");
            byte[] expected = Encoding.UTF8.GetBytes("ICE ICE BABY");

            var underTest = Crypto.UnpadBlock(input);

            underTest.Should().BeEquivalentTo(expected);
        }

        [TestMethod]
        public void Test_15_PCKS7_Padding_Validation_Failure()
        {
            // Test one
            byte[] inputA = Encoding.UTF8.GetBytes("ICE ICE BABY\x05\x05\x05\x05");
            Action actionA = () => Crypto.UnpadBlock(inputA);
            actionA.Should().Throw<Cryptopals.Exceptions.InvalidPaddingException>();

            // Test two
            byte[] inputB = Encoding.UTF8.GetBytes("ICE ICE BABY\x01\x02\x03\x04");
            Action actionB = () => Crypto.UnpadBlock(inputB);
            actionB.Should().Throw<Cryptopals.Exceptions.InvalidPaddingException>();
        }
    }
}

