using System;
using System.Text;
using System.Linq;
using MoreLinq.Extensions;

namespace Cryptopals.SetOne
{
	public class XorBruteforce
	{
        public static string XOR(string a, string b)
        {
            byte[] aHex = Convert.FromHexString(a);
            byte[] bHex = Convert.FromHexString(b);

            return Convert.ToHexString(XOR(aHex, bHex));
        }

        public static byte[] XOR(byte[] data, byte[] key)
        {
            int keyLen = key.Length;
            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; ++i)
            {
                result[i] = (byte)(data[i] ^ key[i % keyLen]);
            }

            return result;
        }

        public static BruteforceResult FindSingleCharacterKey(byte[] input)
		{
			byte[] possibleKeys = Enumerable.Range(1, 254).Select(i => (byte)i).ToArray();

			var possibleResults = possibleKeys.ToDictionary(
				key => key, key => XorBruteforce.XOR(input, new byte[] { key })
				);

			var resultsScored = possibleResults
				.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Sum(GetScore))
				.OrderByDescending(kvp => kvp.Value);

			var bestResult = resultsScored
				.First();

			return new BruteforceResult() {
				Input = input,
				Key = new byte[] { bestResult.Key },
				Decoded = possibleResults[bestResult.Key],
				Score = bestResult.Value,
			};
		}

		public static BruteforceResult FindKey(byte[] input, int keysize)
        {
            List<byte[]> chunked = XorBruteforce.ChunkAndTranspose(input, keysize);

            var bfResults = chunked.Select(FindSingleCharacterKey);
            byte[] key = bfResults.SelectMany(r => r.Key).ToArray();
            string keyStr = Encoding.UTF8.GetString(key);

            byte[] decrypted = XorBruteforce.XOR(input, key);
            string decryptedStr = Encoding.UTF8.GetString(decrypted);

            return new BruteforceResult()
            {
                Input = input,
                Decoded = decrypted,
                Key = key,
                Score = decrypted.Select(GetScore).Sum()
            };
        }

        public static BruteforceResult DetectSingleCharacterXOR(List<string> data)
		{
			var results = data.Select(Convert.FromHexString)
				.Select(FindSingleCharacterKey);

			return results.OrderDescending().First();
		}

		public static int GetScore(byte c)
		{
			return GetScore((char)c);
		}

		private static int GetScore(char c)
		{
			if (char.IsControl(c)) { return -1; }

			if (char.IsAsciiLetterOrDigit(c) | char.IsWhiteSpace(c)) { return 1; }

			return 0;
		}

		public static int CalculateHammingDistance(byte[] first, byte[] second)
		{
			return XorBruteforce.XOR(first, second)
				.Sum(i => byte.PopCount(i));
		}

		public static decimal CalculateAverageHammingDistance(byte[] data, int blockSize)
		{
			return Enumerable.Range(0, (data.Length / blockSize) - 1).Average(block =>
			{
				var fst = data.Skip(block * blockSize).Take(blockSize).ToArray() ?? Array.Empty<byte>();
				var snd = data.Skip(block * blockSize + blockSize).Take(blockSize).ToArray() ?? Array.Empty<byte>();

				int distance = XorBruteforce.CalculateHammingDistance(fst, snd);

				return (decimal)distance / (decimal)blockSize;
			});
        }

		public static int[] FindBestKeysize(byte[] data, IEnumerable<int> possibleKeylengths, int numberOfItems = 3) {
            Dictionary<int, decimal> result = possibleKeylengths.ToDictionary(
				len => len, len => CalculateAverageHammingDistance(data, len)
				);

			var ordered = result.OrderBy(kvp => kvp.Value);
			int[] best = ordered.Take(numberOfItems).Select(kvp => kvp.Key).ToArray();

			return best;
        }


		public static List<byte[]> ChunkAndTranspose(byte[] data, int chunkSize)
		{
			return data.Chunk(chunkSize)
				.Transpose()
				.Select(inner => inner.ToArray())
				.ToList();
		}
    }



	public class BruteforceResult : IComparable
	{
		public byte[] Input { get; set; }    = Array.Empty<byte>();
		public byte[] Decoded { get; set; }  = Array.Empty<byte>();
        public byte[] Key { get; set; }      = Array.Empty<byte>();
		public int Score { get; set; }       = 0;

		public string DecodedStr { get => Encoding.UTF8.GetString(Decoded); }
        public string DecodedKey { get => Encoding.UTF8.GetString(Key); }

        public int CompareTo(object? obj)
        {
			if (obj == null) return 1;

			BruteforceResult? other = obj as BruteforceResult;
			if (other != null)
				return this.Score.CompareTo(other.Score);
			else
				throw new ArgumentException($"Object is not of type {nameof(BruteforceResult)}");
        }
    }
}