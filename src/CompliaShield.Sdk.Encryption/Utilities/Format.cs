
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;

    public class Format
    {
        public static string StripInvalidXmlCharacters(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return string.Empty;
            }

            input = Regex.Replace(input, RegExPatterns.InvalidXmlCharacters, string.Empty);
            return input;
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                           .Where(x => x % 2 == 0)
                           .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                           .ToArray();
        }

        public static bool TryParseBase64Encoded(string input, out byte[] value)
        {
            try
            {
                // If no exception is caught, then it is possibly a base64 encoded string
                value = Convert.FromBase64String(input);
                return (input.Replace(" ", "").Length % 4 == 0);
            }
            catch
            {
                // If exception is caught, then it is not a base64 encoded string
                value = null;
                return false;
            }
        }     

        private static readonly Regex r = new Regex(@"^[0-9A-Fa-f\r\n]+$");

        public static bool VerifyHex(string hex)
        {
            return r.Match(hex).Success;
        }
    }
}
