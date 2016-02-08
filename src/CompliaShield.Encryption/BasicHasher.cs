
namespace CompliaShield.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using CompliaShield.Encryption.Extensions;
    using CompliaShield.Encryption.Utilities;

    public class BasicHasher
    {

        public static string GetMd5Hash(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            var hashBytes = GetMd5HashBytes(preHashBytes);
            return hashBytes.ToHexString();
        }

        public static byte[] GetMd5HashBytes(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            return GetMd5HashBytes(preHashBytes);
        }

        private static byte[] GetMd5HashBytes(byte[] input)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                return md5Hash.ComputeHash(input);
            }
        }

        public static string GetSha1Hash(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            var hashBytes = GetSha1HashBytes(preHashBytes);
            return hashBytes.ToHexString();
        }

        public static byte[] GetSha1HashBytes(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            return GetSha1HashBytes(preHashBytes);
        }

        public static string GetConcatenatedString(IEnumerable<string> input)
        {

            if (input == null || !input.Any())
            {
                throw new ArgumentException("input");
            }
            string stringToHash = "";
            foreach (var str in input)
            {
                stringToHash += str;
            }
            return stringToHash;
        }


        #region helpers


        private static byte[] GetSha1HashBytes(byte[] input)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(input);
            }
        }

        private static byte[] ConvertObjectToPreHashBytes(object input)
        {
            byte[] preHashBytes = null;
            if (input is string)
            {
                preHashBytes = Encoding.UTF8.GetBytes((string)input);
            }

            else if (input is byte[])
            {
                preHashBytes = (byte[])input;
            }
            else
            {
                if (input.GetType().IsSerializable)
                {
                    preHashBytes = Serializer.SerializeToByteArray(input);
                }
                else
                {
                    try
                    {
                        preHashBytes = Encoding.UTF8.GetBytes(Serializer.SerializeToJson(input));
                    }
                    catch (Exception)
                    {
                        throw new SerializationException(string.Format("Object of type '{0}' is not marked as serializable. No hash could be created.  Simple objects can use JSON serialization. If JSON serialization cannot be performed and the object is not marked as serializable, the hash generation will fail.", input.GetType().FullName));
                    }
                }
            }
            return preHashBytes;
        }

        #endregion


    }
}
