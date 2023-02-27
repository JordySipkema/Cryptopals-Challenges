using System;
using System.Security.Cryptography;
using System.Text;
using Cryptopals.SetOne;
using FluentAssertions;
using Newtonsoft.Json.Linq;

namespace Cryptopals_Tests;

[TestClass]
public class SetOneTests
{
    [TestMethod]
    public void Test_1_ConvertHexToBase64()
    {
        string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        string expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        Utils.ConvertHexToBase64(input).Should().Be(expected);
    }

    [TestMethod]
    public void Test_2_FixedXOR()
    {
        string A = "1c0111001f010100061a024b53535009181c";
        string B = "686974207468652062756c6c277320657965";
        string expected = "746865206b696420646f6e277420706c6179";

        // Using "BeEquivalentTo" because it ignores casing.
        XorBruteforce.XOR(A, B).Should().BeEquivalentTo(expected);
    }

    [TestMethod]
    public void Test_3_SingleCharacterXOR()
    {
        // Arrange
        byte[] input = Convert.FromHexString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        byte[] expectedResult = Encoding.UTF8.GetBytes("Cooking MC's like a pound of bacon");
        byte[] expectedKey = new byte[] { 0x58 };

        // Act
        var result = XorBruteforce.FindSingleCharacterKey(input);

        // Assert
        result.Input.Should().BeEquivalentTo(input, "because the input should match.");
        result.Decoded.Should().BeEquivalentTo(expectedResult);
        result.Key.Should().BeEquivalentTo(expectedKey);
    }

    [TestMethod]
    public void Test_4_DetectSingleCharacterXOR()
    {
        // Arrange
        var input = File.ReadAllLines("./Input/04.txt").ToList();

        // Act
        var result = XorBruteforce.DetectSingleCharacterXOR(input);

        // Assert
        Encoding.UTF8.GetString(result.Decoded).Should().Be("Now that the party is jumping\n");
        result.Key.Should().BeEquivalentTo(new byte[] { 53 });
    }

    [TestMethod]
    public void Test_5_RepeatingKeyXOR()
    {
        // Arrange
        byte[] input = Convert.FromBase64String("QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxlCkkgZ28gY3Jhenkgd2hlbiBJIGhlYXIgYSBjeW1iYWw=");
        byte[] expected = Convert.FromHexString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

        // Act
        var key = Encoding.UTF8.GetBytes("ICE");
        var result = XorBruteforce.XOR(input, key);

        // Assert
        result.Should().BeEquivalentTo(expected);
    }

    [TestMethod]
    public void Test_6a_HammingDistance()
    {
        // Arrange
        byte[] stringA = Encoding.UTF8.GetBytes("this is a test");
        byte[] stringB = Encoding.UTF8.GetBytes("wokka wokka!!!");
        int expected = 37;

        // Act
        var result = XorBruteforce.CalculateHammingDistance(stringA, stringB);

        // Assert
        result.Should().Be(expected);
    }

    [TestMethod]
    public void Test_6b_FindHammingDistanceForKeysize()
    {
        string inputB64 = File.ReadAllText("./Input/06-loremipsum.txt");
        byte[] input = Convert.FromBase64String(inputB64);

        IEnumerable<int> possibleKeylengths = Enumerable.Range(2, 38); // Define a list with possible keysizes ( 2 to 40 incl )

        int[] bestKeysizes = XorBruteforce.FindBestKeysize(input, possibleKeylengths);

        bestKeysizes.Select(i => i % 4 == 0).Should().NotContain(false);
    }

    [TestMethod]
    public void Test_6c_ChunkAndTranspose()
    {
        byte[] testData = Encoding.UTF8.GetBytes("abcdeabcdeabcdeabcdeabc");

        List<byte[]> result = XorBruteforce.ChunkAndTranspose(testData, 5);

        result[0].Should().AllSatisfy(item => item.Equals((byte)'a'));
        result[1].Should().AllSatisfy(item => item.Equals((byte)'b'));
        result[2].Should().AllSatisfy(item => item.Equals((byte)'c'));
        result[3].Should().AllSatisfy(item => item.Equals((byte)'d'));
        result[4].Should().AllSatisfy(item => item.Equals((byte)'e'));
    }

    [TestMethod]
    public void Test_6d_BreakKnownCipherText()
    {
        // Arrange
        string inputB64 = File.ReadAllText("./Input/06-loremipsum.txt");
        byte[] input = Convert.FromBase64String(inputB64);

        IEnumerable<int> possibleKeylengths = Enumerable.Range(2, 38); // Define a list with possible keysizes ( 2 to 40 incl )
        int[] bestKeysizes = XorBruteforce.FindBestKeysize(input, possibleKeylengths);

        // Act
        var results = bestKeysizes.Select(keysize => XorBruteforce.FindKey(input, keysize));

        // Assert
        bestKeysizes.Select(i => i % 4 == 0).Should().NotContain(false);
        results.Should().NotBeEmpty();

        BruteforceResult result = results.OrderDescending().First();
        result.DecodedStr.Should().StartWithEquivalentOf("Lorem ipsum dolor sit amet");
    }

    [TestMethod]
    public void Test_6e_BreakCipherText()
    {
        // Arrange
        string inputB64 = File.ReadAllText("./Input/06.txt");
        byte[] input = Convert.FromBase64String(inputB64);

        IEnumerable<int> possibleKeylengths = Enumerable.Range(2, 38); // Define a list with possible keysizes ( 2 to 40 incl )
        int[] bestKeysizes = XorBruteforce.FindBestKeysize(input, possibleKeylengths);

        // Act
        var results = bestKeysizes.Select(keysize => XorBruteforce.FindKey(input, keysize));

        // Assert
        results.Should().NotBeEmpty();

        BruteforceResult result = results.OrderDescending().First();

        result.DecodedKey.Should().Be("Terminator X: Bring the noise");
        result.DecodedStr.Should().StartWithEquivalentOf("I'm back");
    }

    [TestMethod]
    public void Test_7_DecryptAesEcb()
    {
        // Arrange
        string inputB64 = File.ReadAllText("./Input/07.txt");
        byte[] input = Convert.FromBase64String(inputB64);
        byte[] key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");

        // Act
        Aes aes = Aes.Create();
        aes.Key = key;
        byte[] decrypted = aes.DecryptEcb(input, PaddingMode.None);

        // Assert
        BruteforceResult result = new() { Decoded = decrypted, Key = key };
        result.DecodedStr.Should().StartWithEquivalentOf("I'm back and I'm ringin' the bell");
    }

    [TestMethod]
    public void Test_8_DetectAesEcb()
    {
        List<byte[]> inputArray = File.ReadAllLines("./Input/08.txt")
            .Select(Convert.FromHexString)
            .ToList();


        var results = inputArray.ToDictionary(
            key => Convert.ToHexString(key),
            value => hasRepeatingPatterns(value, 16))
            .Where(kvp => kvp.Value);

        results.Should().HaveCount(1, "because there is one AES ECB encrypted string.");
        results.First().Key.Should().StartWithEquivalentOf("D880619740A8A19B7840A8A31C8");
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


/*

    1, Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

    2. Write a function to compute the edit distance/Hamming distance between two strings.
       The Hamming distance is just the number of differing bits.

    3. For each KEYSIZE, take the first KEYSIZE worth of bytes,
       and the second KEYSIZE worth of bytes, and find the edit distance between them.
       Normalize this result by dividing by KEYSIZE.

    4. The KEYSIZE with the smallest normalized edit distance is probably the key.
       You could proceed perhaps with the smallest 2-3 KEYSIZE values.
       Or take 4 KEYSIZE blocks instead of 2 and average the distances.

    5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

    6. Now transpose the blocks: make a block that is the first byte of every block,
       and a block that is the second byte of every block, and so on.

    7. Solve each block as if it was single-character XOR.
       You already have code to do this.

    8. For each block, the single-byte XOR key that produces the best looking
       histogram is the repeating-key XOR key byte for that block.
       Put them together and you have the key.

 */