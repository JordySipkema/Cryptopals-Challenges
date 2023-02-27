using System;
using System.Text;

namespace Cryptopals.SetOne
{
	public static class Utils
	{
		public static string ConvertHexToBase64(string hexString)
		{
            // hex-string is converted to byte-array
            byte[] stringBytes = Convert.FromHexString(hexString);

            // byte-array is converted base64-string
            string res = Convert.ToBase64String(stringBytes);

            return res;
        }
	}
}

