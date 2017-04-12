
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

    using CompliaShield.Sdk.Cryptography.Encryption.Keys;
    using CompliaShield.Sdk.Cryptography.Extensions;
    using CompliaShield.Sdk.Cryptography.Utilities;


    public sealed class AsymmetricEncryptor
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

        public static async Task<string> EncryptToBase64StringAsync(SecureString passwordToProtect, IPublicKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            //var rsa = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(publicKey);
            return await EncryptToBase64StringAsync(passwordToProtect, publicKey, null);
        }

        //[Obsolete]
        //public static string EncryptToBase64String(SecureString passwordToProtect, string keyId, RSACryptoServiceProvider publicKey)
        //{
        //    return EncryptToBase64String(passwordToProtect, keyId, publicKey, null, null);
        //}


        ///// <summary>
        ///// This may be used to secure a password for symmetric encryption.
        ///// </summary>
        ///// <param name="passwordToProtect"></param>
        ///// <param name="publicKey"></param>
        ///// <returns></returns>
        //[Obsolete("Use the IPublicKey infrastructure")]
        //public static string EncryptToBase64String(SecureString passwordToProtect, string key1Id, RSACryptoServiceProvider publicKey1, string key2Id, RSACryptoServiceProvider publicKey2)
        //{
        //    // Use a 4-byte array to fill it with random bytes and convert it then
        //    // to an integer value.
        //    byte[] plainBytes;
        //    //byte[] encryptedBytes = null;

        //    plainBytes = passwordToProtect.ToByteArray();

        //    var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
        //    var asymObj = asymEnc.EncryptObject(plainBytes, key1Id, publicKey1, key2Id, publicKey2);
        //    var json = Serializer.SerializeToJson(asymObj);
        //    var bytes = Encoding.UTF8.GetBytes(json);
        //    return Convert.ToBase64String(bytes);
        //}

        /// <summary>
        /// This may be used to secure a password for symmetric encryption.
        /// </summary>
        /// <param name="passwordToProtect"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static async Task<string> EncryptToBase64StringAsync(SecureString passwordToProtect, IPublicKey publicKey1, IPublicKey publicKey2)
        {
            // Use a 4-byte array to fill it with random bytes and convert it then
            // to an integer value.
            byte[] plainBytes;
            //byte[] encryptedBytes = null;

            plainBytes = passwordToProtect.ToByteArray();

            var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
            var asymObj = await asymEnc.EncryptObject_PrivateAsync(plainBytes, publicKey1, publicKey2);
            var json = Serializer.SerializeToJson(asymObj);
            var bytes = Encoding.UTF8.GetBytes(json);
            return Convert.ToBase64String(bytes);
        }

        public static SecureString DecryptFromBase64String(string encryptedValueAsBase64String, IPrivateKey privateKey)
        {
            return DecryptFromBase64String(encryptedValueAsBase64String, privateKey, null);
        }

        public static async Task<SecureString> DecryptFromBase64StringAsync(string encryptedValueAsBase64String, IPrivateKey privateKey)
        {
            return await DecryptFromBase64StringAsync(encryptedValueAsBase64String, privateKey, null);
        }

        public static SecureString DecryptFromBase64String(string encryptedValueAsBase64String, IPrivateKey privateKey1, IPrivateKey privateKey2)
        {
            return AsyncHelper.RunSync(() => DecryptFromBase64StringAsync(encryptedValueAsBase64String, privateKey1, privateKey2));
        }

        /// <summary>
        /// This may be used to decrypte a password used for symmetric encryption.
        /// </summary>
        /// <param name="encryptedValueAsBase64String"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static async Task<SecureString> DecryptFromBase64StringAsync(string encryptedValueAsBase64String, IPrivateKey privateKey1, IPrivateKey privateKey2)
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
            plainBytes = (byte[])await asymEnc.DecryptObjectAsync(asymEncObj, privateKey1, privateKey2);

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

        //[Obsolete("Prefer the async implementation of IPublicKey")]
        //public AsymmetricallyEncryptedObject EncryptObject(object input, string keyId, RSACryptoServiceProvider publicKey)
        //{
        //    return this.EncryptObject_Private(input, keyId, publicKey, null, null);
        //}

        //[Obsolete("Prefer the async implementation of IPublicKey")]
        //public AsymmetricallyEncryptedObject EncryptObject(object input, string key1Id, RSACryptoServiceProvider publicKey1, string key2Id, RSACryptoServiceProvider publicKey2)
        //{
        //    return AsyncHelper.RunSync(() => this.EncryptObject_PrivateAsync(input, key1Id, publicKey1, key2Id, publicKey2);
        //}

        public AsymmetricallyEncryptedObject EncryptObject(object input, IPublicKey publicKey1)
        {
            return AsyncHelper.RunSync(() => this.EncryptObjectAsync(input, publicKey1, null));
        }

        public async Task<AsymmetricallyEncryptedObject> EncryptObjectAsync(object input, IPublicKey publicKey)
        {
            // temporary... need to shift to create a password and wrap or unwrap in future
            //var rsa = publicKey.ToRSACryptoServiceProvider();
            return await this.EncryptObject_PrivateAsync(input, publicKey, null);
        }


        public AsymmetricallyEncryptedObject EncryptObject(object input, IPublicKey publicKey1, IPublicKey publicKey2)
        {
            return AsyncHelper.RunSync(() => this.EncryptObjectAsync(input, publicKey1, publicKey2));
        }

        public async Task<AsymmetricallyEncryptedObject> EncryptObjectAsync(object input, IPublicKey publicKey1, IPublicKey publicKey2)
        {
            // temporary... need to shift to create a password and wrap or unwrap in future
            //var rsa1 = publicKey1.ToRSACryptoServiceProvider();
            //var rsa2 = publicKey2.ToRSACryptoServiceProvider();
            return await this.EncryptObject_PrivateAsync(input, publicKey1, publicKey2);
        }

        public object DecryptObject(AsymmetricallyEncryptedObject input, IPrivateKey privateKey)
        {
            return AsyncHelper.RunSync(() => this.DecryptObjectAsync(input, privateKey));
        }

        public async Task<object> DecryptObjectAsync(AsymmetricallyEncryptedObject input, IPrivateKey privateKey)
        {
            return await this.DecryptObject_PrivateAsync(input, privateKey, null);
        }

        public object DecryptObject(AsymmetricallyEncryptedObject input, IPrivateKey privateKey1, IPrivateKey privateKey2)
        {
            return AsyncHelper.RunSync(() => this.DecryptObject_PrivateAsync(input, privateKey1, privateKey2));
        }

        public async Task<object> DecryptObjectAsync(AsymmetricallyEncryptedObject input, IPrivateKey privateKey1, IPrivateKey privateKey2)
        {
            return await this.DecryptObject_PrivateAsync(input, privateKey1, privateKey2);
        }

        #region helpers

        private async Task<AsymmetricallyEncryptedObject> EncryptObject_PrivateAsync(object input, IPublicKey publicKey1, IPublicKey publicKey2)
        {
            if (input == null)
            {
                throw new ArgumentNullException(nameof(input));
            }
            if (publicKey1 == null)
            {
                throw new ArgumentNullException(nameof(publicKey1));
            }

            //if (string.IsNullOrEmpty(key1Id))
            //{
            //    throw new ArgumentException("key1Id");
            //}
            //if (publicKey2 != null && string.IsNullOrEmpty(key2Id))
            //{
            //    throw new ArgumentException("key2Id");
            //}
            //if (!string.IsNullOrEmpty(key2Id) && publicKey2 == null)
            //{
            //    throw new ArgumentNullException("publicKey2");
            //}

            // password lengths



            int pwLen = 32;
            //var pwMinLen = pwLen;
            //var pwMaxLen = pwLen; // 40;

            if (this.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_1000)
            {
                pwLen = 40;
                //// up the pw size
                //pwMinLen = 40;
                //pwMaxLen = 40;
            }

            //if (pwMinLen < 32)
            //{
            //    throw new NotImplementedException("pwMinLen is at least 32 bytes");
            //}

            //if (pwMinLen == pwMaxLen)
            //{
            //    pwLen = pwMaxLen;
            //}
            //else
            //{
            //    pwLen = rand.RandomNumber(pwMinLen, pwMaxLen);
            //}


            byte[] passPhraseAsBytes = null;
            byte[] passPhrase2AsBytes = null;

            string passPhrase = null;
            string passPhrase2 = null;

            var cryptoSvc = RNGCryptoServiceProvider.Create();

            if (this.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
            {
                // legacy uses a string
                var rand = new RandomGenerator();
                passPhrase = rand.GenerateSecretCodeUrlSafe(pwLen, pwLen); // pwMinLen, pwMaxLen);
                passPhraseAsBytes = Serializer.SerializeToByteArray(passPhrase);
                if (publicKey2 != null)
                {
                    passPhrase2 = rand.GenerateSecretCodeUrlSafe(pwLen, pwLen); // pwMinLen, pwMaxLen);
                    passPhrase2AsBytes = Serializer.SerializeToByteArray(passPhrase2);
                }
            }
            else
            {
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
                var encRes = await publicKey1.WrapKeyAsync(passPhraseAsBytes);
                encryptedPassPhraseAsBytes = encRes;
                asymEncObj = new AsymmetricallyEncryptedObject()
                {
                    KeyId = publicKey1.KeyId,
                    Reference = encryptedPassPhraseAsBytes
                };
                encryptionPassPhrase = passPhraseAsBytes;
            }
            else
            {
                // double passwords
                var dualPw = new DualKeyProtectedPassword();

                // get encryption from key1
                var encRes1 = await publicKey1.WrapKeyAsync(passPhraseAsBytes);
                dualPw.EncryptedPassphrase1 = encRes1;

                // get encryption from key2
                var encRes2 = await publicKey2.WrapKeyAsync(passPhrase2AsBytes);
                dualPw.EncryptedPassphrase2 = encRes2;

                encryptedPassPhraseAsBytes = Encoding.UTF8.GetBytes(Serializer.SerializeToJson(dualPw));

                asymEncObj = new AsymmetricallyEncryptedObject()
                {
                    KeyId = publicKey1.KeyId,
                    Key2Id = publicKey2.KeyId,
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
#pragma warning disable 0618
                asymEncObj.Data = BasicEncryptor.EncryptObject(input, passPhrase + passPhrase2, out cipher);
#pragma warning restore 0618
                asymEncObj.CipherText = cipher;
                asymEncObj.AsymmetricStrategy = AsymmetricStrategyOption.Legacy_Aes2; // critical!!!
            }
            else if (this.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_20000)
            {
                byte[] inputAsBytes = Serializer.SerializeToByteArray(input);
                asymEncObj.Data = AesEncryptor.Encrypt20000(inputAsBytes, encryptionPassPhrase);
                asymEncObj.AsymmetricStrategy = AsymmetricStrategyOption.Aes256_20000; // critical!!!
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

            passPhraseAsBytes.ClearByteArray();
            passPhrase2AsBytes.ClearByteArray();

            return asymEncObj;
        }

        private class DualKeyProtectedPassword
        {
            public byte[] EncryptedPassphrase1 { get; set; }

            public byte[] EncryptedPassphrase2 { get; set; }
        }

        private async Task<object> DecryptObject_PrivateAsync(AsymmetricallyEncryptedObject input, IPrivateKey privateKey1, IPrivateKey privateKey2)
        {

            // Variables
            byte[] encryptedPassphraseAsBytes = null;
            encryptedPassphraseAsBytes = input.Reference;

            byte[] passphraseAsBytes = null;
            string passPhrase = null; // used for the legacy
            if (privateKey2 == null)
            {
                passphraseAsBytes = await privateKey1.UnwrapKeyAsync(encryptedPassphraseAsBytes);
                if (input.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
                {
                    passPhrase = (string)Serializer.DeserializeFromByteArray(passphraseAsBytes);
                }
            }
            else
            {
                var dualPwJson = Encoding.UTF8.GetString(encryptedPassphraseAsBytes);
                var dualPw = Serializer.DeserializeFromJson<DualKeyProtectedPassword>(dualPwJson);

                var passPhrase1Bytes = await privateKey1.UnwrapKeyAsync(dualPw.EncryptedPassphrase1);
                var passPhrase2Bytes = await privateKey2.UnwrapKeyAsync(dualPw.EncryptedPassphrase2);

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
                //passPhrase1Bytes.ClearByteArray();
                //passPhrase2Bytes.ClearByteArray();
            }

            object output = null;

            // handle the different strategies
            if (input.AsymmetricStrategy == AsymmetricStrategyOption.Undefined || input.AsymmetricStrategy == AsymmetricStrategyOption.Legacy_Aes2)
            {
                // deserialize the object using the legacy serialization to a string
                // unavoidable to preserve
#pragma warning disable 0618
                output = BasicEncryptor.DecryptObject(input.Data, input.CipherText, passPhrase);
#pragma warning restore 0618
            }
            else if (input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_5)
            {
                // decryption knows the iterations
                var decryptedObjectAsBytes = AesEncryptor.Decrypt(input.Data, passphraseAsBytes);
                output = Serializer.DeserializeFromByteArray(decryptedObjectAsBytes);
            }
            else if (input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_1000 || input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_5 || input.AsymmetricStrategy == AsymmetricStrategyOption.Aes256_20000)
            {
                // decryption knows the iterations
                var decryptedObjectAsBytes = AesEncryptor.Decrypt(input.Data, passphraseAsBytes);
                output = Serializer.DeserializeFromByteArray(decryptedObjectAsBytes);
            }
            else
            {
                throw new NotImplementedException(string.Format("AsymmetricStrategyOption '{0}' not implemented.", input.AsymmetricStrategy.ToString()));
            }

            passphraseAsBytes.ClearByteArray();

            return output;
        }

        #endregion
    }
}
