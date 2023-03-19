namespace Cryptopals.Helpers {
    
    public class ByteArray {
        public static byte[] Concat(byte[] first, byte[] second) {
            byte[] result = new byte[first.Length + second.Length];
            first.CopyTo(result, 0);
            second.CopyTo(result, second.Length);

            return result;
        }

        public static byte[] Concat(byte[] first, byte[] second, byte[] third)
        {
            byte[] result = new byte[first.Length + second.Length + third.Length];
            first.CopyTo(result, 0);
            second.CopyTo(result, second.Length);
            third.CopyTo(result, first.Length + second.Length);

            return result;
        }

        public static byte[] Concat(byte[] first, byte second) {
            byte[] result = new byte[first.Length + 1];
            first.CopyTo(result, 0);
            result[first.Length] = second;

            return result;
        }
    }


}
