
namespace CompliaShield.Sdk.Cryptography.Encryption
{

    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    using CompliaShield.Sdk.Cryptography.Extensions;
    using CompliaShield.Sdk.Cryptography.Utilities;


    public class AsymmetricEncryptor
    {

        public AsymmetricStrategyOption AsymmetricStrategy { get; set; }

        #region .ctors

        public AsymmetricEncryptor()
        {
            // set to the current preferred strategy
            this.AsymmetricStrategy = AsymmetricStrategyOption.Aes256_1000;
        }

        public AsymmetricEncryptor(AsymmetricStrategyOption asymmetricStrategy)
        {
            // set to the current preferred strategy
            this.AsymmetricStrategy = asymmetricStrategy;
        }

        #endregion
        
        #region key generation

        public static string EncryptToBase64String(SecureString passwordToProtect, string keyId, RSACryptoServiceProvider publicKey)
        {
            return EncryptToBase64String(passwordToProtect, keyId, publicKey, null, null);
        }

        /// <summary>
        /// This may be used to secure a password for symmetric encryption.
        /// </summary>
        /// <param name="passwordToProtect"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string EncryptToBase64String(SecureString passwordToProtect, string key1Id, RSACryptoServiceProvider publicKey1, string key2Id, RSACryptoServiceProvider publicKey2)
        {
            // Use a 4-byte array to fill it with random bytes and convert it then
            // to an integer value.
            byte[] plainBytes;
            byte[] encryptedBytes = null;

            plainBytes = passwordToProtect.ToByteArray();

            var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
            var asymObj = asymEnc.EncryptObject(plainBytes, key1Id, publicKey1, key2Id, publicKey2);
            var json = Serializer.SerializeToJson(asymObj);
            var bytes = Encoding.UTF8.GetBytes(json);
            return Convert.ToBase64String(bytes);
        }



        public static SecureString DecryptFromBase64String(string encryptedValueAsBase64String, RSACryptoServiceProvider privateKey)
        {
            return DecryptFromBase64String(encryptedValueAsBase64String, privateKey, null);
        }

        /// <summary>
        /// This may be used to decrypte a password used for symmetric encryption.
        /// </summary>
        /// <param name="encryptedValueAsBase64String"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static SecureString DecryptFromBase64String(string encryptedValueAsBase64String, RSACryptoServiceProvider privateKey1, RSACryptoServiceProvider privateKey2)
        {

            if (string.IsNullOrEmpty(encryptedValueAsBase64String))
            {
                throw new ArgumentException("encryptedValueAsBase64String");
            }

            byte[] plainBytes = null;

            // Read encrypted data
            var bytes = Convert.FromBase64String(encryptedValueAsBase64String);
            var json = Encoding.UTF8.GetString(bytes);
            var asymEncObj = Serializer.DeserializeFromJson<AsymmetricallyEncryptedObject>(json);

            // deserialize the object
            var asymEnc = new AsymmetricEncryptor();
            plainBytes = (byte[])asymEnc.DecryptObject(asymEncObj, privateKey1, privateKey2);

            var secureString = new SecureString();
            var chars = System.Text.Encoding.UTF8.GetChars(plainBytes);
            foreach (var c in chars)
            {
                secureString.AppendChar(c);
            }
            for (int i = 0; i < chars.Length; i++)
            {
                // clear chars array
                chars[i] = 'X';
            }
            chars = null;
            return secureString;
        }

        #endregion

        public AsymmetricallyEncryptedObject EncryptObject(object input, string keyId, RSACryptoServiceProvider publicKey)
        {
            return this.EncryptObject_Private(input, keyId, publicKey, null, null);
        }

        public AsymmetricallyEncryptedObject EncryptObject(object input, string key1Id, RSACryptoServiceProvider publicKey1, string key2Id, RSACryptoServiceProvider publicKey2)
        {
            return this.EncryptObject_Private(input, key1Id, publicKey1, key2Id, publicKey2);
        }

        public object DecryptObject(AsymmetricallyEncryptedObject input, RSACryptoServiceProvider privateKey)
        {
            return this.DecryptObject_Private(input, privateKey, null);
        }

        public object DecryptObject(AsymmetricallyEncryptedObject input, RSACryptoServiceProvider privateKey1, RSACryptoServiceProvider privateKey2)
        {
            return this.DecryptObject_Private(input, privateKey1, privateKey2);
        }

        #region helpers

        private AsymmetricallyEncryptedObject EncryptObject_Private(object input, string key1Id, RSACryptoServiceProvider publicKey1, string key2Id, RSACryptoServiceProvider publicKey2)
        {
            if (string.IsNullOrEmpty(key1Id))
            {
                throw new ArgumentException("key1Id");
            }
            if (publicKey2 != null && string.IsNullOrEmpty(key2Id))
            {
                throw new ArgumentException("key2Id");
            }
            if (!string.IsNullOrEmpty(key2Id) && publicKey2 == null)
            {
                throw new ArgumentNullException("publicKey2");
            }

            // password lengths
            var pwMinLen = 32;
            var pwMaxLen = 40;
            if (this.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_1000)
            {
                // up the pw size
                pwMinLen = 40;
                pwMaxLen = 65;
            }
            var rand = new RandomGenerator();
            var pwLen = rand.RandomNumber(pwMinLen, pwMaxLen);

            byte[] passPhraseAsBytes = null;
            byte[] passPhrase2AsBytes = null;

            string passPhrase = null;
            string passPhrase2 = null;

            if (this.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
            {
                // legacy uses a string
                passPhrase = rand.RandomPassword(pwMinLen, pwMaxLen);
                passPhraseAsBytes = Serializer.SerializeToByteArray(passPhrase);
                if (publicKey2 != null)
                {
                    passPhrase2 = rand.RandomPassword(pwMinLen, pwMaxLen);
                    passPhrase2AsBytes = Serializer.SerializeToByteArray(passPhrase2);
                }
            }
            else
            {
                var cryptoSvc = RNGCryptoServiceProvider.Create();
                passPhraseAsBytes = new byte[pwLen];
                cryptoSvc.GetBytes(passPhraseAsBytes);
                if (publicKey2 != null)
                {
                    passPhrase2AsBytes = new byte[pwLen];
                    cryptoSvc.GetBytes(passPhrase2AsBytes);
                }
            }

            byte[] encryptedPassPhraseAsBytes = null;
            AsymmetricallyEncryptedObject asymEncObj = null;

            byte[] encryptionPassPhrase = null;

            // if there are two keys, then we double encrypt the passphrase
            if (publicKey2 == null)
            {
                encryptedPassPhraseAsBytes = publicKey1.Encrypt(passPhraseAsBytes, false);
                asymEncObj = new AsymmetricallyEncryptedObject()
                {
                    KeyId = key1Id,
                    Reference = encryptedPassPhraseAsBytes
                };
                encryptionPassPhrase = passPhraseAsBytes;
            }
            else
            {
                // double passwords
                var dualPw = new DualKeyProtectedPassword()
                {
                    EncryptedPassphrase1 = publicKey1.Encrypt(passPhraseAsBytes, false),
                    EncryptedPassphrase2 = publicKey2.Encrypt(passPhrase2AsBytes, false)
                };

                encryptedPassPhraseAsBytes = Encoding.UTF8.GetBytes(Serializer.SerializeToJson(dualPw));

                asymEncObj = new AsymmetricallyEncryptedObject()
                {
                    KeyId = key1Id,
                    Key2Id = key2Id,
                    Reference = encryptedPassPhraseAsBytes
                };

                encryptionPassPhrase = passPhraseAsBytes.Concat(passPhrase2AsBytes).ToArray();
            }

            // handle the different strategies
            // handle the different strategies
            if (this.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
            {

                // this is the revised legacy handling that has been enhanced

                // Note that the passPhrase is a string, but the reference taht is stored is
                // -----> Serializer.SerializeToByteArray(passPhrase);
                //        This is not a straight forward string to byte array conversion using encoding.
                //        And the decrypte expects to use this serializer method.

                string cipher;
                asymEncObj.Data = BasicEncryptor.EncryptObject(input, passPhrase + passPhrase2, out cipher);
                asymEncObj.CipherText = cipher;
                asymEncObj.AsymmetricStrategy = AsymmetricStrategyOption.Legacy_Aes2; // critical!!!
            }
            else if (this.AsymmetricStrategy == AsymmetricStrategyOption.Undefined || this.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_1000)
            {
                byte[] inputAsBytes = Serializer.SerializeToByteArray(input);
                asymEncObj.Data = AesEncryptor.Encrypt1000(inputAsBytes, encryptionPassPhrase);
                asymEncObj.AsymmetricStrategy = AsymmetricStrategyOption.Aes256_1000; // critical!!!
            }
            else if (this.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_5)
            {
                byte[] inputAsBytes = Serializer.SerializeToByteArray(input);
                asymEncObj.Data = AesEncryptor.Encrypt5(inputAsBytes, encryptionPassPhrase);
                asymEncObj.AsymmetricStrategy = AsymmetricStrategyOption.Aes256_5; // critical!!!
            }
            else
            {
                throw new NotImplementedException(string.Format("AsymmetricStrategyOption '{0}' not implemented.", this.AsymmetricStrategy.ToString()));
            }
            return asymEncObj;
        }

        private class DualKeyProtectedPassword
        {
            public byte[] EncryptedPassphrase1 { get; set; }

            public byte[] EncryptedPassphrase2 { get; set; }
        }

        private object DecryptObject_Private(AsymmetricallyEncryptedObject input, RSACryptoServiceProvider privateKey1, RSACryptoServiceProvider privateKey2)
        {

            // Variables
            byte[] encryptedPassphraseAsBytes = null;
            encryptedPassphraseAsBytes = input.Reference;

            byte[] passphraseAsBytes = null;
            string passPhrase = null; // used for the legacy
            if (privateKey2 == null)
            {
                passphraseAsBytes = privateKey1.Decrypt(encryptedPassphraseAsBytes, false);
                if (input.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
                {
                    passPhrase = (string)Serializer.DeserializeFromByteArray(passphraseAsBytes);
                }
            }
            else
            {
                var dualPwJson = Encoding.UTF8.GetString(encryptedPassphraseAsBytes);
                var dualPw = Serializer.DeserializeFromJson<DualKeyProtectedPassword>(dualPwJson);

                var passPhrase1Bytes = privateKey1.Decrypt(dualPw.EncryptedPassphrase1, false);
                var passPhrase2Bytes = privateKey2.Decrypt(dualPw.EncryptedPassphrase2, false);

                if (input.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
                {
                    var passPhrase1 = (string)Serializer.DeserializeFromByteArray(passPhrase1Bytes);
                    var passPhrase2 = (string)Serializer.DeserializeFromByteArray(passPhrase2Bytes);
                    passPhrase = passPhrase1 + passPhrase2;
                }
                else
                {
                    // generate the full passphrase
                    passphraseAsBytes = passPhrase1Bytes.Concat(passPhrase2Bytes).ToArray();
                }
            }

            object output = null;

            // handle the different strategies
            if (input.AsymmetricStrategy == AsymmetricStrategyOption.Undefined || input.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
            {
                // deserialize the object using the legacy serialization to a string
                // unavoidable to preserve
                output = BasicEncryptor.DecryptObject(input.Data, input.CipherText, passPhrase);
            }
            else if (input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_5)
            {
                // decryption knows the iterations
                var decryptedObjectAsBytes = AesEncryptor.Decrypt(input.Data, passphraseAsBytes);
                output = Serializer.DeserializeFromByteArray(decryptedObjectAsBytes);
            }
            else if (input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_1000 || input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_5)
            {
                // decryption knows the iterations
                var decryptedObjectAsBytes = AesEncryptor.Decrypt(input.Data, passphraseAsBytes);
                output = Serializer.DeserializeFromByteArray(decryptedObjectAsBytes);
            }
            else
            {
                throw new NotImplementedException(string.Format("AsymmetricStrategyOption '{0}' not implemented.", input.AsymmetricStrategy.ToString()));
            }
            return output;
        }

        #endregion
    }
}
