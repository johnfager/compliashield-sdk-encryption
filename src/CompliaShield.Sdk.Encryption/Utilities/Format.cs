
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
    }
}
