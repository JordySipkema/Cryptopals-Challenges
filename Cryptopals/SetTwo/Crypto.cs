using System;

namespace Cryptopals.SetTwo
{
    public class Crypto
    {
        public delegate byte[] CryptoFunction(byte[] data);

        public Crypto() { }

        public static byte[] PadBlock(byte[] block, int blocksize)
        {
            int length = block.Length;
            int modLen = length % blocksize;
            int paddingToAdd = blocksize - modLen;

            Span<byte> destination = new byte[length + paddingToAdd];

            block.CopyTo(destination);
            destination.Slice(length, paddingToAdd).Fill((byte)paddingToAdd);

            return destination.ToArray();
        }

        public static byte[] UnpadBlock(byte[] block)
        {
            short paddingLength = block.Last();
            int length = block.Length - paddingLength;

            return block.Take(length).ToArray();
        }

        public static byte[] PadBlockInFront(byte[] block, int blocksize) {
            int length = block.Length;
            int modLen = length % blocksize;
            int paddingToAdd = blocksize - modLen;

            Span<byte> destination = new byte[length + paddingToAdd];

            destination.Fill(0x00);
            block.CopyTo(destination.Slice(paddingToAdd, block.Length));

            return destination.ToArray();
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

        public static int DetectBlocksize(CryptoFunction func)
        {
            int inputLength = 1;
            int outputLength_current;
            int outputLength_1char = func(new byte[inputLength]).Length;

            do
            {
                inputLength++;
                outputLength_current = func(new byte[inputLength]).Length;
            } while (outputLength_1char == outputLength_current);

            return outputLength_current - outputLength_1char;
        }
    }
}
