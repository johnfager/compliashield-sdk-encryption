
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Text;
    
    public static class JsonWebTokenUtility
    {
        /// <summary>
        /// Accepts a string, encodes it to UTF8 bytes, then to a Base64 string, then encodes for URL safe values per JWT specification.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Base64UrlEncodeForJson(string json)
        {
            var bytes = Encoding.UTF8.GetBytes(json);
            return Base64UrlEncodeForJson(bytes);
        }

        /// <summary>
        /// Accepts byte array, encodes it to base64, then encodes for URL safe values per JWT specification.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string Base64UrlEncodeForJson(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        /// <remarks>From JWT spec</remarks>
        public static string UrlEncodedToBase64(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new FormatException("Illegal base64url string!");
            }
            return output;
        }

        /// <remarks>From JWT spec</remarks>
        public static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break;  // One pad char
                default: throw new FormatException("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

        /// <summary>
        /// Accepts a URL encoded Base64 string and returns the UT8 string value.
        /// </summary>
        /// <param name="input">A Base64 URL encoded string.</param>
        /// <returns></returns>
        public static string Base64UrlDecodeToUtf8String(string input)
        {
            var converted = Base64UrlDecode(input);
            return Encoding.UTF8.GetString(converted);
        }

    }
}
