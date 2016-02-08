
namespace CompliaShield.Encryption.Utilities
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

    }
}
