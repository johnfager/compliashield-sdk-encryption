

namespace CompliaShield.Sdk.Cryptography.Encryption
{

    using System;
    using System.IO;
    using System.Text;
    using System.Security.Cryptography;
    using System.Runtime.Serialization;
    using CompliaShield.Sdk.Cryptography.Utilities;

    /// <summary>
    /// Encrypts and decrypts data
    /// </summary>
    /// <remarks></remarks>
    [Obsolete("BasicEncryptor is obsolete. Use AesEncryptor instead.")]
    public class BasicEncryptor
    {

        /// <summary> 
        /// Encrypts specified plaintext using Rijndael symmetric key algorithm 
        /// and returns a base64-encoded result. 
        /// </summary> 
        /// <param name="plainText"> 
        /// Plaintext value to be encrypted. 
        /// </param> 
        /// <param name="passPhrase"> 
        /// Passphrase from which a pseudo-random password will be derived. The 
        /// derived password will be used to generate the encryption key. 
        /// Passphrase can be any string. In this example we assume that this 
        /// passphrase is an ASCII string. 
        /// </param> 
        /// <returns> 
        /// Encrypted value formatted as a base64-encoded string. 
        /// </returns> 
        public static string Encrypt(string plainText, string passPhrase)
        {
            return Encrypt_Private(plainText, passPhrase, false);
        }

        public static string Encrypt(string plainText, string passPhrase, bool useBase36)
        {
            return Encrypt_Private(plainText, passPhrase, useBase36);
        }

        public static byte[] EncryptObject(object input, string passPhrase, out string cipher)
        {
            return EncryptObject_Private(input, passPhrase, out cipher);
        }

        private static byte[] EncryptObject_Private(object input, string passPhrase, out string cipher)
        {
            RandomGenerator randGen = new RandomGenerator();

            string strSalt = randGen.RandomString(8);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(strSalt);

            // Convert our plaintext into a byte array. 
            // Let us assume that plaintext contains UTF8-encoded characters. 
            byte[] plainTextBytes = Serializer.SerializeToByteArray(input);

            // First, we must create a password, from which the key will be derived. 
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations. 
            Rfc2898DeriveBytes pw = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 2);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = pw.GetBytes(256 / 8);

            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();

            RandomGenerator randGen2 = new RandomGenerator();

            string strIv = randGen2.RandomString(16);
            // Convert strings into byte arrays. 
            // Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(strIv);

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes. 
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

            // Define memory stream which will be used to hold encrypted data. 
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption). 
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            // Start encrypting. 
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting. 
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array. 
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams. 
            memoryStream.Close();
            cryptoStream.Close();

            //// Convert encrypted data into a base64-encoded string. 
            //string cipherText = Convert.ToBase64String(cipherTextBytes);

            //// reconvert cipherText to bytes
            //byte[] cipherBytes = Convert.FromBase64String(cipherText);

            cipher = strIv + strSalt;

            return cipherTextBytes;
        }

        private static string Encrypt_Private(string plainText, string passPhrase, bool useBase36)
        {

            RandomGenerator randGen = new RandomGenerator();

            string strSalt = randGen.RandomAlphaNumeric(8);
            byte[] saltValueBytes;

            saltValueBytes = Encoding.ASCII.GetBytes(strSalt);

            // Convert our plaintext into a byte array. 
            // Let us assume that plaintext contains UTF8-encoded characters. 
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // First, we must create a password, from which the key will be derived. 
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations. 
            Rfc2898DeriveBytes pw = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 2);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = pw.GetBytes(256 / 8);

            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();

            RandomGenerator randGen2 = new RandomGenerator();

            string strIv = randGen2.RandomAlphaNumeric(16);
            // Convert strings into byte arrays. 
            // Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 

            byte[] initVectorBytes;
            initVectorBytes = Encoding.ASCII.GetBytes(strIv);

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes. 
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

            // Define memory stream which will be used to hold encrypted data. 
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption). 
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            // Start encrypting. 
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting. 
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array. 
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams. 
            memoryStream.Close();
            cryptoStream.Close();

            // Convert encrypted data into a base64-encoded string. 
            string cipherText;

            if (useBase36)
            {
                cipherText = Base36.ByteArrayToBase36String(cipherTextBytes);
                cipherText = cipherText.ToLower();
            }
            else
            {
                cipherText = Convert.ToBase64String(cipherTextBytes);
            }

            // Return encrypted string. 

            string strReturn = strIv + strSalt + cipherText;

            return strReturn;

            //Return cipherText

        }


        public static object DecryptObject(byte[] input, string cipherText, string passPhrase)
        {
            return DecryptObject_Private(input, cipherText, passPhrase, null);
        }

        public static object DecryptObject(byte[] input, string cipherText, string passPhrase, SerializationBinder serializationBinder)
        {
            return DecryptObject_Private(input, cipherText, passPhrase, serializationBinder);
        }

        /// <summary> 
        /// Decrypts specified ciphertext using Rijndael symmetric key algorithm. 
        /// </summary> 
        /// <param name="cipherText"> 
        /// Base64-formatted ciphertext value. 
        /// </param> 
        /// <param name="passPhrase"> 
        /// Passphrase from which a pseudo-random password will be derived. The 
        /// derived password will be used to generate the encryption key. 
        /// Passphrase can be any string. In this example we assume that this 
        /// passphrase is an ASCII string. 
        /// </param> 
        /// <returns> 
        /// Decrypted string value. 
        /// </returns> 
        /// <remarks> 
        /// Most of the logic in this function is similar to the Encrypt 
        /// logic. In order for decryption to work, all parameters of this function 
        /// - except cipherText value - must match the corresponding parameters of 
        /// the Encrypt function which was called to generate the 
        /// ciphertext. 
        /// </remarks> 
        private static object DecryptObject_Private(byte[] encryptedObject, string cipherText, string passPhrase, SerializationBinder serializationBinder)
        {
            // Convert strings defining encryption key characteristics into byte 
            // arrays. Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 

            if (string.IsNullOrEmpty(cipherText))
            {
                throw new InvalidOperationException("Invalid cipherText");
            }

            if (cipherText.Length < 23)
            {
                throw new InvalidOperationException("Invalid cipherText");
            }

            string strIv = cipherText.Substring(0, 16);
            string strSalt = cipherText.Substring(16, 8);

            byte[] initVectorBytes = Encoding.ASCII.GetBytes(strIv);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(strSalt);

            // Convert our ciphertext into a byte array. 
            byte[] cipherTextBytes = encryptedObject;

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using 
            // the specified hash algorithm. Password creation can be done in 
            // several iterations. 
            //Dim password As New PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations)

            Rfc2898DeriveBytes pw = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 2);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = pw.GetBytes(256 / 8);

            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            try
            {
                // Generate decryptor from the existing key bytes and initialization 
                // vector. Key size will be defined based on the number of the key 
                // bytes. 
                ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);

                // Define memory stream which will be used to hold encrypted data. 
                MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

                // Define cryptographic stream (always use Read mode for encryption). 
                CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

                // Since at this point we don't know what the size of decrypted data 
                // will be, allocate the buffer long enough to hold ciphertext; 
                // plaintext is never longer than ciphertext. 
                byte[] plainBytes = new byte[cipherTextBytes.Length];

                // Start decrypting. 

                int decryptedByteCount = cryptoStream.Read(plainBytes, 0, plainBytes.Length);

                // Close both streams. 
                memoryStream.Close();
                cryptoStream.Close();

                object output;
                if (serializationBinder == null)
                {
                    output = Serializer.DeserializeFromByteArray(plainBytes);
                }
                else
                {
                    output = Serializer.DeserializeFromByteArray(plainBytes, serializationBinder);
                }

                return output;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        // ------------------------------

        public static string Decrypt(string cipherText, string passPhrase)
        {
            return Decrypt_Private(cipherText, passPhrase, false);
        }

        public static string Decrypt(string cipherText, string passPhrase, bool useBase36)
        {
            return Decrypt_Private(cipherText, passPhrase, useBase36);
        }

        /// <summary> 
        /// Decrypts specified ciphertext using Rijndael symmetric key algorithm. 
        /// </summary> 
        /// <param name="cipherText"> 
        /// Base64-formatted ciphertext value. 
        /// </param> 
        /// <param name="passPhrase"> 
        /// Passphrase from which a pseudo-random password will be derived. The 
        /// derived password will be used to generate the encryption key. 
        /// Passphrase can be any string. In this example we assume that this 
        /// passphrase is an ASCII string. 
        /// </param> 
        /// <returns> 
        /// Decrypted string value. 
        /// </returns> 
        /// <remarks> 
        /// Most of the logic in this function is similar to the Encrypt 
        /// logic. In order for decryption to work, all parameters of this function 
        /// - except cipherText value - must match the corresponding parameters of 
        /// the Encrypt function which was called to generate the 
        /// ciphertext. 
        /// </remarks> 
        private static string Decrypt_Private(string cipherText, string passPhrase, bool useBase36)
        {
            // Convert strings defining encryption key characteristics into byte 
            // arrays. Let us assume that strings only contain ASCII codes. 
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 
            // encoding. 

            if (string.IsNullOrEmpty(cipherText))
            {
                throw new InvalidOperationException("Invalid cipherText");
            }

            if (cipherText.Length < 23)
            {
                throw new InvalidOperationException("Invalid cipherText");
            }

            string strIv = cipherText.Substring(0, 16);

            string strSalt = cipherText.Substring(16, 8);

            string strCipher = cipherText.Substring(24);


            byte[] initVectorBytes = Encoding.ASCII.GetBytes(strIv);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(strSalt);

            // Convert our ciphertext into a byte array. 
            byte[] cipherTextBytes;

            if (useBase36)
            {
                strCipher = strCipher.ToUpper();
                cipherTextBytes = Base36.Base36StringToByteArray(strCipher);
            }
            else
            {
                cipherTextBytes = Convert.FromBase64String(strCipher);
            }

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using 
            // the specified hash algorithm. Password creation can be done in 
            // several iterations. 
            //Dim password As New PasswordDeriveBytes(passPhrase, saltValueBytes, hashAlgorithm, passwordIterations)

            Rfc2898DeriveBytes pw = new Rfc2898DeriveBytes(passPhrase, saltValueBytes, 2);

            // Use the password to generate pseudo-random bytes for the encryption 
            // key. Specify the size of the key in bytes (instead of bits). 
            byte[] keyBytes = pw.GetBytes(256 / 8);

            // Create uninitialized Rijndael encryption object. 
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining 
            // (CBC). Use default options for other symmetric key parameters. 
            symmetricKey.Mode = CipherMode.CBC;

            // Generate decryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes. 
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);

            // Define memory stream which will be used to hold encrypted data. 
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            // Define cryptographic stream (always use Read mode for encryption). 
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            // Since at this point we don't know what the size of decrypted data 
            // will be, allocate the buffer long enough to hold ciphertext; 
            // plaintext is never longer than ciphertext. 
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            // Start decrypting. 
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            // Close both streams. 
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded. 
            string plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);

            // Return decrypted string. 
            return plainText;
        }
    }
}
