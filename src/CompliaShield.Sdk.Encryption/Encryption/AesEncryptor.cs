
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections.Generic;
    using CompliaShield.Sdk.Cryptography.Extensions;
    using CompliaShield.Sdk.Cryptography.Utilities;


    public sealed class AesEncryptor
    {
        #region basic

        public static string Decrypt(string encryptedString, SecureString passPhrase)
        {
            var passwordBytes = passPhrase.ToByteArray();
            var output = Decrypt(encryptedString, passwordBytes);
            passwordBytes.ClearByteArray();
            return output;
        }

        public static string Decrypt(string encryptedString, byte[] passwordBytes)
        {
            return Decrypt_Private(encryptedString, passwordBytes, false);
        }

        public static string Decrypt(string encryptedString, SecureString passPhrase, bool useBase36)
        {
            var passwordBytes = passPhrase.ToByteArray();
            var output = Decrypt(encryptedString, passwordBytes, useBase36);
            passwordBytes.ClearByteArray();
            return output;
        }

        public static string Decrypt(string encryptedString, byte[] passwordBytes, bool useBase36)
        {
            return Decrypt_Private(encryptedString, passwordBytes, useBase36);
        }


        public static byte[] Decrypt(byte[] encryptionPayload, SecureString passPhrase)
        {
            var passwordBytes = passPhrase.ToByteArray();
            var output = Decrypt(encryptionPayload, passwordBytes);
            passwordBytes.ClearByteArray();
            return output;
        }

        public static byte[] Decrypt(byte[] encryptionPayload, byte[] passwordBytes)
        {
            return Decrypt_Private(encryptionPayload, passwordBytes);
        }

        /// <summary>
        /// AES 256 with 5 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        public static string Encrypt5(string plainText, SecureString passPhrase)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 5, false);
        }

        /// <summary>
        /// AES 256 with 5 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <param name="useBase36">True returns a base36 encoding set to lowercase for legibility.</param>
        /// <returns></returns>
        public static string Encrypt5(string plainText, SecureString passPhrase, bool useBase36)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 5, useBase36);
        }


        /// <summary>
        /// AES 256 with 5 iterations.
        /// </summary>
        /// <param name="unencryptedBytes"></param>
        /// <param name="passPhraseAsBytes"></param>
        /// <returns></returns>
        public static byte[] Encrypt5(byte[] unencryptedBytes, byte[] passPhraseAsBytes)
        {
            return Encrypt_Private_v1(unencryptedBytes, passPhraseAsBytes, 5);
        }

        #endregion


        #region AES200

        /// <summary>
        /// AES 256 with 200 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        public static string Encrypt200(string plainText, SecureString passPhrase)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 200, false);
        }
        
        /// <summary>
        /// AES 256 with 200 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <param name="useBase36">True returns a base36 encoding set to lowercase for legibility.</param>
        /// <returns></returns>
        public static string Encrypt200(string plainText, SecureString passPhrase, bool useBase36)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 200, useBase36);
        }

        /// <summary>
        /// AES 256 with 200 iterations.
        /// </summary>
        /// <param name="unencryptedBytes"></param>
        /// <param name="passPhraseAsBytes"></param>
        /// <returns></returns>
        public static byte[] Encrypt200(byte[] unencryptedBytes, byte[] passPhraseAsBytes)
        {
            return Encrypt_Private_v1(unencryptedBytes, passPhraseAsBytes, 200);
        }

        #endregion

        #region AES1000

        /// <summary>
        /// AES 256 with 1000 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        public static string Encrypt1000(string plainText, SecureString passPhrase)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 1000, false);
        }

        /// <summary>
        /// AES 256 with 1000 iterations.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="passPhrase"></param>
        /// <param name="useBase36">True returns a base36 encoding set to lowercase for legibility.</param>
        /// <returns></returns>
        public static string Encrypt1000(string plainText, SecureString passPhrase, bool useBase36)
        {
            return Encrypt_Private_v1(plainText, passPhrase, 1000, useBase36);
        }

        /// <summary>
        /// AES 256 with 1000 iterations.
        /// </summary>
        /// <param name="unencryptedBytes"></param>
        /// <param name="passPhraseAsBytes"></param>
        /// <returns></returns>
        public static byte[] Encrypt1000(byte[] unencryptedBytes, byte[] passPhraseAsBytes)
        {
            return Encrypt_Private_v1(unencryptedBytes, passPhraseAsBytes, 1000);
        }

        #endregion

        #region helpers

        private static string Encrypt_Private_v1(string plainText, SecureString passPhrase, int iterations, bool useBase36)
        {
            // in version 1, we use UTF8 for our plain text value to bytes
            byte[] unencryptedBytes = Encoding.UTF8.GetBytes(plainText);
            var passPhraseAsBytes = passPhrase.ToByteArray();
            var payload = Encrypt_Private_v1(unencryptedBytes, passPhraseAsBytes, iterations);
            passPhraseAsBytes.ClearByteArray(); // modify the byte array

            string cipherText;
            if (useBase36)
            {
                cipherText = Base36.ByteArrayToBase36String(payload);
                cipherText = cipherText.ToLower();
            }
            else
            {
                cipherText = Convert.ToBase64String(payload);
            }
            // Return encrypted string witht the leading 8 characters as the salt
            return cipherText;
        }

        private static byte[] Encrypt_Private_v1(byte[] unencryptedBytes, byte[] passPhraseAsBytes, int iterations)
        {

            byte iterationSetting;
            int saltLength;
            int ivLength = 16;
            switch (iterations)
            {
                case 5:
                    iterationSetting = (byte)2;
                    saltLength = 8;
                    break;
                case 200:
                    iterationSetting = (byte)3;
                    saltLength = 32;
                    break;
                case 1000:
                    iterationSetting = (byte)10;
                    saltLength = 32;
                    break;
                default:
                    throw new NotImplementedException(string.Format("'{0}' iterations is not supported.", iterations.ToString()));
            }

            // current version for future compatability and the iteration value
            byte[] versionAndIterationBytes = new byte[] { (byte)1, iterationSetting };

            // The salt bytes must be at least 8 bytes
            var saltBytes = new byte[saltLength];
            RNGCryptoServiceProvider.Create().GetBytes(saltBytes);

            // The IV bytes
            var ivBytes = new byte[ivLength];
            RNGCryptoServiceProvider.Create().GetBytes(ivBytes);

            // encrypt the value
            byte[] encryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.Mode = CipherMode.CBC;
                    var key = new Rfc2898DeriveBytes(passPhraseAsBytes, saltBytes, iterations);
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.IV = ivBytes; // random bytes
                    aes.Key = key.GetBytes(aes.KeySize / 8);

                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(unencryptedBytes, 0, unencryptedBytes.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            // combine the bytes into a single payload
            byte[] payload = versionAndIterationBytes.Concat(saltBytes).Concat(ivBytes).Concat(encryptedBytes).ToArray();
            return payload;

        }

        private static byte[] Decrypt_Private(byte[] encryptedBytes, byte[] passwordBytes)
        {
            if (encryptedBytes == null || !encryptedBytes.Any())
            {
                throw new InvalidOperationException("Invalid encryptedString");
            }

            byte version;

            // we can implement new versions down the line
            version = encryptedBytes[0];

            // only v1 is implemented for now
            if (version == 1)
            {
                var decryptedBytes = Decrypt_Private_v1(encryptedBytes, passwordBytes);
                return decryptedBytes;
            }

            // if version is not implemented, throw ex
            throw new NotImplementedException(string.Format("Version '{0} not impleneted.", version.ToString()));
        }

        private static string Decrypt_Private(string encryptedString, byte[] passwordBytes, bool useBase36)
        {

            if (string.IsNullOrEmpty(encryptedString))
            {
                throw new InvalidOperationException("Invalid encryptedString");
            }

            if (encryptedString.Length < 10)
            {
                throw new InvalidOperationException("Invalid encryptedString");
            }

            byte[] encryptedStringAsBytes;
            byte version;

            if (useBase36)
            {
                var encryptedStringUpper = encryptedString.ToUpper(); // always upper on base36
                encryptedStringAsBytes = Base36.Base36StringToByteArray(encryptedString);
            }
            else
            {
                encryptedStringAsBytes = Convert.FromBase64String(encryptedString);
            }

            // we can implement new versions down the line
            version = encryptedStringAsBytes[0];

            // only v1 is implemented for now
            if (version == 1)
            {
                var decryptedBytes = Decrypt_Private_v1(encryptedStringAsBytes, passwordBytes);
                // use UTF8 string
                string plainText = Encoding.UTF8.GetString(decryptedBytes);

                // Return decrypted string. 
                return plainText;
            }

            // if version is not implemented, throw ex
            throw new NotImplementedException(string.Format("Version '{0} not impleneted.", version.ToString()));
        }

        /// <summary>
        /// Class to remain locked in based on the version stored in the first byte of the payload.
        /// </summary>
        /// <param name="encryptedPayload"></param>
        /// <param name="passPhrase"></param>
        /// <param name="useBase36"></param>
        /// <returns></returns>
        private static byte[] Decrypt_Private_v1(byte[] encryptedPayload, byte[] passwordBytes)
        {
            // first byte is the version of encoding
            // next 8 bytes are the salt
            // rest of the encryptedBytes is the encrypted data

            int versionAndIterationByteCount = 2;
            int ivByteCount = 16;
            int saltByteCount;

            byte version = encryptedPayload[0];
            // check the version
            if (version != 1)
            {
                throw new InvalidOperationException(string.Format("Version '{0}' was passed. Version must be 1.", version.ToString()));
            }

            // retreive the iterations
            byte iterationsSetting = encryptedPayload[1];
            int iterations;
            switch (iterationsSetting)
            {
                case 2:
                    iterations = 5;
                    saltByteCount = 8;
                    break;
                case 3:
                    iterations = 200;
                    saltByteCount = 32;
                    break;
                case 10:
                    iterations = 1000;
                    saltByteCount = 32;
                    break;
                default:
                    throw new FormatException(string.Format("IterationsSetting '{0}' is not supported. Only 2 and 10 are supported in version {1}.", iterationsSetting.ToString(), version.ToString()));
            }

            // retrieve the salt
            var saltBytes = new byte[saltByteCount];
            for (int i = 0; i < saltByteCount; i++)
            {
                // use our traditional 0 based index but skip the version bytes from the payload
                saltBytes[i] = encryptedPayload[i + versionAndIterationByteCount];
            }

            // retrieve the iv
            var ivBytes = new byte[ivByteCount];
            for (int i = 0; i < ivByteCount; i++)
            {
                // use our traditional 0 based index but skip the version bytes from the payload
                ivBytes[i] = encryptedPayload[i + versionAndIterationByteCount + saltByteCount];
            }

            // the bytes to be decrypted    
            int leadingByteCount = versionAndIterationByteCount + saltByteCount + ivByteCount;
            byte[] bytesToBeDecrypted = new byte[encryptedPayload.Length - leadingByteCount];
            for (int i = 0; i < encryptedPayload.Length - leadingByteCount; i++)
            {
                bytesToBeDecrypted[i] = encryptedPayload[i + leadingByteCount];
            }

            // decrypt the bytes
            byte[] decryptedBytes = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = ivBytes;
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }

            return decryptedBytes;


        }

        #endregion

    }
}
