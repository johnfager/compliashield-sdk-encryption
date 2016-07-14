
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
    using X509Certificates;
    using System.Threading.Tasks;
    using Encryption.Keys;
    [TestClass]
    public class TestProtectedCertificateEncryption : _baseTest
    {


        [TestMethod]
        public void TestAes1000WithCertificate()
        {
            var cert2 = LoadCertificate();

            //var publicKey = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(cert2);
            var keyProtector = X509CertificateHelper.GetKeyEncryptionKey(cert2);

            // generate a protected key
            var gen = new ProtectedX509Certificate2Generator();

            var policy = new CertificatePolicy()
            {
                CommonName = "Testing protected certs",
                AllPurposes = true,
                ValidForDays = 2
            };

            var protectedKey = Task.Run(() => gen.IssueNewCertificateAsync(keyProtector, policy)).GetAwaiter().GetResult();

            // save the key to test
            var keyOutputFilePath = (CERT_FOLDER + "temp\\pk-" + protectedKey.KeyId + ".kpk");
            var fi = new FileInfo(keyOutputFilePath);
            if (!fi.Directory.Exists)
            {
                fi.Directory.Create();
            }
            var bytes = Task.Run(() => protectedKey.ToByteArrayAsync()).GetAwaiter().GetResult();
            File.WriteAllBytes(fi.FullName, bytes);
            Console.WriteLine(fi.FullName);
            var list = new List<string>();
            var listEnc = new List<AsymmetricallyEncryptedObject>();

            using (var privateKey = Task.Run(() => protectedKey.ToKeyEncyrptionKeyAsync(keyProtector)).GetAwaiter().GetResult())
            {
                var publicKey = privateKey.PublicKey.Key as RSACryptoServiceProvider;

                File.WriteAllText(fi.FullName + "_A.cer", privateKey.PublicKeyToPEM());
                
                int length = 100;
                var rand = new RandomGenerator();
                for (int i = 0; i < length; i++)
                {
                    var stringToEncrypt = Guid.NewGuid().ToString("N") + ":* d’une secrétairE chargée des affaires des étudiants de la section";
                    list.Add(stringToEncrypt);
                    var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
                    var asymObj = asymEnc.EncryptObjectAsync(stringToEncrypt, cert2.Thumbprint.ToString().ToLower(), privateKey).GetAwaiter().GetResult();
                    listEnc.Add(asymObj);
                    var decrypted = asymEnc.DecryptObjectAsync(asymObj, privateKey).GetAwaiter().GetResult();
                    Assert.AreEqual(stringToEncrypt, decrypted);
                }
            }

            // lets reload a new private key

            var fileBytes = File.ReadAllBytes(fi.FullName);
            var encKey = new AsymmetricallyEncryptedObject();
            encKey.LoadFromByteArray(fileBytes);
            var protectedKey2 = new ProtectedX509Certificate2(protectedKey.KeyId, encKey);

            using (var privateKey = Task.Run(() => protectedKey2.ToKeyEncyrptionKeyAsync(keyProtector)).GetAwaiter().GetResult())
            {
                var publicKey = privateKey.PublicKey.Key as RSACryptoServiceProvider;
                File.WriteAllText(fi.FullName + "_B.cer", privateKey.PublicKeyToPEM());

                var asymEnc = new AsymmetricEncryptor(AsymmetricStrategyOption.Aes256_1000);
                int i = 0;
                foreach (var line in list)
                {
                    var asymObj = listEnc[i];
                    var decrypted = asymEnc.DecryptObject(asymObj, privateKey);
                    Assert.AreEqual(line, decrypted);
                    i++;
                }
            }



        }
    }
}
