
namespace CompliaShield.Sdk.Cryptography.Hashing
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using CompliaShield.Sdk.Cryptography.Extensions;
    using CompliaShield.Sdk.Cryptography.Utilities;

    public class BasicHasher
    {

        public static void ValidateDigestLength(string algorithm, byte[] digest)
        {
            if (digest == null || !digest.Any())
            {
                throw new ArgumentException(nameof(digest));
            }

            algorithm = algorithm.ToUpper();
#pragma warning disable 0618
            switch (algorithm)
            {
                case BasicHasherAlgorithms.MD5:
                    if (digest.Length != 16)
                    {
                        throw new ArgumentException("MD5 digest must be 16 bytes");
                    }
                    break;
                case BasicHasherAlgorithms.SHA1:
                    if (digest.Length != 20)
                    {
                        throw new ArgumentException("SHA1 digest must be 20 bytes");
                    }
                    break;
                case BasicHasherAlgorithms.SHA256:
                    if (digest.Length != 32)
                    {
                        throw new ArgumentException("SHA256 digest must be 32 bytes");
                    }
                    break;
            }
#pragma warning restore 0618
        }

        public static string GetNormalAlgorithm(byte[] digest)
        {
            if (digest == null || !digest.Any())
            {
                throw new ArgumentException(nameof(digest));
            }
#pragma warning disable 0618
            switch (digest.Length)
            {
                case 16:
                    return BasicHasherAlgorithms.MD5;
                case 20:
                    return BasicHasherAlgorithms.SHA1;
                case 32:
                    return BasicHasherAlgorithms.SHA256;
                default:
                    throw new NotImplementedException(string.Format("Algorithm for digest with '{0}' bytes is not implemented.", digest.Count().ToString()));
            }
#pragma warning restore 0618
        }

        public static string GetNormalAlgorithm(string hex)
        {
#pragma warning disable 0618
            switch (hex.Length)
            {
                case 32:
                    return BasicHasherAlgorithms.MD5;
                case 40:
                    return BasicHasherAlgorithms.SHA1;
                case 64:
                    return BasicHasherAlgorithms.SHA256;
                default:
                    throw new NotImplementedException(string.Format("Algorithm for digest with '{0}' bytes is not implemented.", hex.Count().ToString()));
            }
#pragma warning restore 0618
        }

        public static string GetHash(object input, string algorithm)
        {
            var hashBytes = GetHashBytes(input, algorithm);
            return hashBytes.ToHexString();
        }

        public static byte[] GetHashBytes(object input, string algorithm)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            algorithm = BasicHasherAlgorithms.VerifyAndMapToAlogrithm(algorithm);
            var preHashBytes = ConvertObjectToPreHashBytes(input);
#pragma warning disable 0618
            switch (algorithm)
            {
                case BasicHasherAlgorithms.MD5:
                    return GetMd5HashBytes(preHashBytes);
                case BasicHasherAlgorithms.SHA1:
                    return GetSha1HashBytes(preHashBytes);
                case BasicHasherAlgorithms.SHA256:
                    return GetSha256HashBytes(preHashBytes);
                default:
                    throw new NotImplementedException(string.Format("Algorithm '{0}' is not supported.", algorithm));
            }
#pragma warning restore 0618
        }

        [Obsolete("Use SHA256 instead.")]
        public static string GetMd5Hash(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            var hashBytes = GetMd5HashBytes(preHashBytes);
            return hashBytes.ToHexString();
        }

        [Obsolete("Use SHA256 instead.")]
        public static byte[] GetMd5HashBytes(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            return GetMd5HashBytes(preHashBytes);
        }

        [Obsolete("Use SHA256 instead.")]
        public static string GetSha1Hash(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            var hashBytes = GetSha1HashBytes(preHashBytes);
            return hashBytes.ToHexString();
        }

        [Obsolete("Use SHA256 instead.")]
        public static byte[] GetSha1HashBytes(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            return GetSha1HashBytes(preHashBytes);
        }

        public static string GetSha256Hash(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            var hashBytes = GetSha256HashBytes(preHashBytes);
            return hashBytes.ToHexString();
        }

        public static byte[] GetSha256HashBytes(object input)
        {
            var preHashBytes = ConvertObjectToPreHashBytes(input);
            return GetSha256HashBytes(preHashBytes);
        }

        /// <summary>
        /// Autodetects whether the input is a HEX encoded or Base64 string and returns bytes.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static byte[] ConvertFromHexOrBase64(string input)
        {
            byte[] bytes;
            try
            {
                if (Format.VerifyHex(input))
                {
                    bytes = Format.HexStringToByteArray(input);
                }
                else if(Format.TryParseBase64Encoded(input, out bytes))
                {
                    return bytes;
                }
            }
            catch (FormatException ex)
            {
                var exMsg = string.Format("input '{0}' is not a valid hex or base64 string.", input);
#if DEBUG
                Console.WriteLine(exMsg);
#endif
                throw new FormatException(exMsg, ex);
            }
            return bytes;
        }

        #region helpers

        private static byte[] GetMd5HashBytes(byte[] input)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                return md5Hash.ComputeHash(input);
            }
        }

        private static byte[] GetSha1HashBytes(byte[] input)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(input);
            }
        }


        private static byte[] GetSha256HashBytes(byte[] input)
        {
            using (SHA256Managed sha256 = new SHA256Managed())
            {
                return sha256.ComputeHash(input);
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
