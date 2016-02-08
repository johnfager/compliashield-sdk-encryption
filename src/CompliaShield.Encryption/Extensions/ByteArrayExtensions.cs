
namespace CompliaShield.Encryption.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security;
    using System.Text;
    using System.Threading.Tasks;

    public static class ByteArrayExtensions
    {
        /// <summary>
        /// Defaults to a lowercase HEX string
        /// </summary>
        /// <param name="helper"></param>
        /// <returns></returns>
        public static string ToHexString(this byte[] helper)
        {
            return ToHexString(helper, true);
        }

        public static byte[] Concatinate(this byte[] helper, byte[] add)
        {
            IEnumerable<byte> rv = helper.Concat(add);
            return rv.ToArray();
        }

        public static SecureString ToSecureString(this byte[] helper)
        {
            var secureString = new SecureString();
            foreach (byte b in helper)
            {
                secureString.AppendChar((char)b);
            }
            // clear the byte array
            for (int i = 0; i < helper.Length; i++)
            {
                helper[i] = (byte)0;
            }
            // set the byte array to null
            helper = null;
            return secureString;
        }

        public static string ToHexString(this byte[] helper, bool lowerCase)
        {
            var hexCode = "x2";
            if (!lowerCase)
            {
                hexCode = "X2";
            }
            // Create a new Stringbuilder to collect the bytes 
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();
            // Loop through each byte of the hashed data  
            // and format each one as a hexadecimal string. 
            for (int i = 0; i < helper.Length; i++)
            {
                sBuilder.Append(helper[i].ToString(hexCode));
            }
            return sBuilder.ToString();
        }

    }
}
