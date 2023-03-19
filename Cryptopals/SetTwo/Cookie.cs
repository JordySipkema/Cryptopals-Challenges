using System;
using System.Linq;
using System.Text;

namespace Cryptopals.SetTwo
{
	public class Cookie
	{
        private static readonly byte[] randomKey = new byte[] {
            0xDE, 0xAD, 0xBE, 0xEF,
            0xFA, 0xCE, 0xB0, 0x0C,
            0x12, 0x34, 0x56, 0x78,
            0xF0, 0xD2, 0xB4, 0x96,
        };

		private readonly Dictionary<string, string> keyValuePairs = new();

        public Cookie() { }

		public static byte[] GetProfileFor(string email)
		{
			string login = GetLoginCookie(email);

			return CustomAesEbc.Encrypt(
				Crypto.PadBlock(Encoding.UTF8.GetBytes(login), 16),
				Cookie.randomKey
				);
		}

		private static string GetLoginCookie(string email)
		{
			Cookie cookie = new Cookie();

			cookie.AddItem("email", SanitizeUserInput(email));
			cookie.AddItem("uid", "10");
			cookie.AddItem("role", "user");

			return cookie.GetString();
		}

		public static Cookie AuthenticateUser(byte[] data)
		{
			string token = Encoding.UTF8.GetString(
				Crypto.UnpadBlock(CustomAesEbc.Decrypt(data, Cookie.randomKey))
				);

			return AuthenticateUser(token);
		}

		private static Cookie AuthenticateUser(string token)
		{
			Cookie cookie = new Cookie();

			foreach (var elem in token.Split("&"))
			{
				string[] kvp = elem.Split("=").ToArray();
				cookie.AddItem(kvp[0], kvp[1]);
			}

			return cookie;
		}

		public bool IsAdmin()
		{
			string? value = keyValuePairs.GetValueOrDefault("role");

			return String.Equals(value, "admin", StringComparison.InvariantCultureIgnoreCase);
		}

		public string GetString()
		{
			return String.Join("&", keyValuePairs.Select(x => $"{x.Key}={x.Value}"));
		}

		private void AddItem(string key, string value)
		{
			keyValuePairs.Add(key, value);
		}

		private static string SanitizeUserInput(string input)
		{
			return input
				.Replace("&", String.Empty)
				.Replace("=", String.Empty);
		}
	}
}

