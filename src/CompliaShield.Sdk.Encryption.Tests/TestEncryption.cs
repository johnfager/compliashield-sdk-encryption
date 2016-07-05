﻿
namespace CompliaShield.Sdk.Cryptography.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Management;
    using System.Reflection;
    using System.Security.Cryptography;
    using Utilities;
    using Encryption;

    [TestClass]
    public class TestEncryption : _baseTest
    {


        [TestMethod]
        public void TestProtectPassword()
        {
            var cert2 = LoadCertificate();
            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            int length = 100;
            var rand = new RandomGenerator();
            for (int i = 0; i < length; i++)
            {
                using (var password = rand.RandomSecureStringPassword(10, 50))
                {
                    var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";

                    // base 64
                    var encryptedBase64 = AesEncryptor.Encrypt1000(stringToEncrypt, password);
                    var decryptedBase64 = AesEncryptor.Decrypt(encryptedBase64, password);
                    Assert.AreEqual(stringToEncrypt, decryptedBase64);

                    // base 36
                    var encryptedBase36 = AesEncryptor.Encrypt1000(stringToEncrypt, password, true);
                    var decryptedBase36 = AesEncryptor.Decrypt(encryptedBase36, password, true);
                    Assert.AreEqual(stringToEncrypt, decryptedBase36);

                    var protectedPwStr = AsymmetricEncryptor.EncryptToBase64String(password, cert2.Thumbprint.ToString().ToLower(), publicKey);

                    var unprotectedPwdStr = AsymmetricEncryptor.DecryptFromBase64String(protectedPwStr, privateKey);

                    var decryptedString = AesEncryptor.Decrypt(encryptedBase64, unprotectedPwdStr);
                    Assert.AreEqual(stringToEncrypt, decryptedString);

                }
            }
        }

        [TestMethod]
        public void TestProtectPasswordDualKey()
        {
            var cert2 = LoadCertificate();
            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            var cert2Dual = LoadCertificate2();
            var publicKey2 = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2Dual);
            var privateKey2 = X509CertificateHelper.GetKeyEncryptionKey(cert2Dual);


            int length = 100;
            var rand = new RandomGenerator();
            for (int i = 0; i < length; i++)
            {
                using (var password = rand.RandomSecureStringPassword(10, 50))
                {
                    var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";

                    // base 64
                    var encryptedBase64 = AesEncryptor.Encrypt1000(stringToEncrypt, password);
                    var decryptedBase64 = AesEncryptor.Decrypt(encryptedBase64, password);
                    Assert.AreEqual(stringToEncrypt, decryptedBase64);

                    // base 36
                    var encryptedBase36 = AesEncryptor.Encrypt1000(stringToEncrypt, password, true);
                    var decryptedBase36 = AesEncryptor.Decrypt(encryptedBase36, password, true);
                    Assert.AreEqual(stringToEncrypt, decryptedBase36);

                    var protectedPwStr = AsymmetricEncryptor.EncryptToBase64String(password, cert2.Thumbprint.ToString().ToLower(), publicKey, cert2Dual.Thumbprint.ToString().ToLower(), publicKey2);

                    var unprotectedPwdStr = AsymmetricEncryptor.DecryptFromBase64String(protectedPwStr, privateKey, privateKey2);

                    var decryptedUnprotectedPw = AesEncryptor.Decrypt(encryptedBase64, unprotectedPwdStr);
                    Assert.AreEqual(stringToEncrypt, decryptedUnprotectedPw);

                }
            }
        }
        
        [TestMethod]
        public void TestAes1000()
        {
            int length = 100;
            var rand = new RandomGenerator();
            for (int i = 0; i < length; i++)
            {
                using (var password = rand.RandomSecureStringPassword(10, 50))
                {
                    var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                    // base 64
                    var encryptedBase64 = AesEncryptor.Encrypt1000(stringToEncrypt, password);
                    var decryptedBase64 = AesEncryptor.Decrypt(encryptedBase64, password);
                    Assert.AreEqual(stringToEncrypt, decryptedBase64);
                    // base 36
                    var encryptedBase36 = AesEncryptor.Encrypt1000(stringToEncrypt, password, true);
                    var decryptedBase36 = AesEncryptor.Decrypt(encryptedBase36, password, true);
                    Assert.AreEqual(stringToEncrypt, decryptedBase36);
                }
            }
        }

        [TestMethod]
        public void TestAes1000_Bytes()
        {
            int length = 100;
            var rand = new RandomGenerator();

            //byte[] entropy = new byte[20];


            for (int i = 0; i < length; i++)
            {

                byte[] newKey = new byte[rand.RandomNumber(75, 88)];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    //rng.GetBytes(entropy);
                    rng.GetBytes(newKey);
                }

                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";

                var bytes = System.Text.Encoding.UTF8.GetBytes(stringToEncrypt);

                // base 64
                var encryptedBytes = AesEncryptor.Encrypt1000(bytes, newKey);
                var decryptedBytes = AesEncryptor.Decrypt(encryptedBytes, newKey);

                Assert.IsTrue(decryptedBytes.SequenceEqual(bytes));

                var decryptedString = System.Text.Encoding.UTF8.GetString(decryptedBytes);
                Assert.AreEqual(stringToEncrypt, decryptedString);


            }
        }

        [TestMethod]
        public void TestAes5_Bytes()
        {
            int length = 100;
            var rand = new RandomGenerator();

            //byte[] entropy = new byte[20];


            for (int i = 0; i < length; i++)
            {

                byte[] newKey = new byte[rand.RandomNumber(75, 88)];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    //rng.GetBytes(entropy);
                    rng.GetBytes(newKey);
                }

                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";

                var bytes = System.Text.Encoding.UTF8.GetBytes(stringToEncrypt);

                // base 64
                var encryptedBytes = AesEncryptor.Encrypt5(bytes, newKey);
                var decryptedBytes = AesEncryptor.Decrypt(encryptedBytes, newKey);

                Assert.IsTrue(decryptedBytes.SequenceEqual(bytes));

                var decryptedString = System.Text.Encoding.UTF8.GetString(decryptedBytes);
                Assert.AreEqual(stringToEncrypt, decryptedString);


            }
        }

        [TestMethod]
        public void TestAesWithCertPw()
        {

            var cert2 = LoadCertificate();

            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Legacy_Aes2);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }
        }

        [TestMethod]
        public void TestAes1000WithCertificateAndSerialization()
        {
            var cert2 = LoadCertificate();

            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            int length = 100;
            var rand = new RandomGenerator();

            //for (int i = 0; i < length; i++)
            //{
            //    var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
            //    var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
            //    var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey);
            //    var decrypted = asymEnc.DecryptObject(asymObj, privateKey);
            //    Assert.AreEqual(stringToEncrypt, decrypted);
            //}

            var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";

            var encryptor = new AsymmetricEncryptor() { AsymmetricStrategy = AsymmetricStrategyOption.Aes256_1000 };
            var asymEncObj = encryptor.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToLower(), publicKey);
            asymEncObj.KeyId = cert2.Thumbprint.ToLower();
            var asymEncObjBytes = Serializer.SerializeToByteArray(asymEncObj);

            // deserialize

            var asymEncObj2 = Serializer.DeserializeFromByteArray(asymEncObjBytes) as AsymmetricallyEncryptedObject;
            Assert.IsNotNull(asymEncObj);
            Assert.IsTrue(!string.IsNullOrEmpty(asymEncObj.KeyId));

        }

        [TestMethod]
        public void TestAes1000WithCertificate()
        {
            var cert2 = LoadCertificate();

            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }
        }

        [TestMethod]
        public void TestAes5WithCertificate()
        {
            var cert2 = LoadCertificate();

            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_5);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }

        }

        [TestMethod]
        public void TestAesWithDualCertPw()
        {

            var cert2 = LoadCertificate();
            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            var cert2Dual = LoadCertificate2();
            var publicKey2 = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2Dual);
            var privateKey2 = X509CertificateHelper.GetKeyEncryptionKey(cert2Dual);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Legacy_Aes2);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey, cert2Dual.Thumbprint.ToString().ToLower(), publicKey2);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey, privateKey2);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }
        }

        [TestMethod]
        public void TestAes1000WithDualCertificate()
        {

            var cert2 = LoadCertificate();
            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            var cert2Dual = LoadCertificate2();
            var publicKey2 = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2Dual);
            var privateKey2 = X509CertificateHelper.GetKeyEncryptionKey(cert2Dual);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey, cert2Dual.Thumbprint.ToString().ToLower(), publicKey2);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey, privateKey2);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }
        }

        [TestMethod]
        public void TestAes5WithDualCertificate()
        {

            var cert2 = LoadCertificate();
            var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var privateKey = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            var cert2Dual = LoadCertificate2();
            var publicKey2 = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2Dual);
            var privateKey2 = X509CertificateHelper.GetKeyEncryptionKey(cert2Dual);

            int length = 100;
            var rand = new RandomGenerator();

            for (int i = 0; i < length; i++)
            {
                var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_5);
                var asymObj = asymEnc.EncryptObject(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), publicKey, cert2Dual.Thumbprint.ToString().ToLower(), publicKey2);
                var decrypted = asymEnc.DecryptObject(asymObj, privateKey, privateKey2);
                Assert.AreEqual(stringToEncrypt, decrypted);
            }
        }

    }

}

