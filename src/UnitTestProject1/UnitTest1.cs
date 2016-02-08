using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.OpenSsl;


namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestClass]
        public class CertificateGeneratorTests
        {

            string _rootPassword = "dkebnqw$23n12l08234n2k34*jebn3-12=0asfme";

            [TestMethod]
            public void GenerateRootCa()
            {
                var sn = "VDP Web Services Root CA";
                string pemValue;
                var rootCa = CertificateGenerator.GenerateRootCertificate(sn, _rootPassword, out pemValue);
                var cert = new X509Certificate2(rootCa, _rootPassword);
                Assert.AreEqual("CN=" + sn, cert.Subject);
            }

            [TestMethod]
            public void GenerateCertificate_Test_ValidCertificate()
            {
                // Arrange
                string subjectName = "localhost";

                var root = System.IO.File.ReadAllBytes(@"C:\_rootCa.pfx");
                //var pemValue = System.IO.File.ReadAllText(@"C:\_rootCa.pem");

                // Act
                string password;
                byte[] actual = CertificateGenerator.GenerateCertificate(subjectName, root, _rootPassword, out password);

                // Assert
                var cert = new X509Certificate2(actual, password);
                Assert.AreEqual("CN=" + subjectName, cert.Subject);
                // Assert.IsInstanceOfType(cert.PrivateKey, typeof(RSACryptoServiceProvider));
            }

            [TestMethod]
            public void EncryptionTestCerts()
            {
                // Files already created and to be used

                // _Test_Encryption.cer
                // _Test_Encryption.pfx
                // _Test_Encryption_Password.txt

                var encryption = new Encryption();

                var toEncrypt = "Hello world!";

                //var toEncrypt = System.IO.File.ReadAllText(@"C:\_large_text.txt");

                //var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);

                var cert = System.IO.File.ReadAllBytes(@"C:\_Test_Encryption.cer");

                var encrypted = encryption.Encrypt(cert, toEncrypt);

                var pfx = System.IO.File.ReadAllBytes(@"C:\_Test_Encryption.pfx");
                var password = System.IO.File.ReadAllText(@"C:\_Test_Encryption_Password.txt");

                var decrypted = (string)encryption.Decrypt(pfx, password, encrypted);

                Assert.AreEqual(toEncrypt, decrypted);

            }

            [TestMethod]
            public void ParsePem()
            {
                var pemValue = System.IO.File.ReadAllText(@"C:\_rootCa.pem");
                var reader = new PemReader(new StringReader(pemValue));


                object obj;

                while ((obj = reader.ReadObject()) != null)
                {
                    var typeStr = obj.GetType().FullName;
                    System.Diagnostics.Debug.WriteLine(typeStr);
                    if (obj is Org.BouncyCastle.X509.X509Certificate)
                    {
                        var cert = (Org.BouncyCastle.X509.X509Certificate)obj;
                    }
                    else if (obj is Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)
                    {
                        var ackp = (Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair)obj;                       
                    }
                }



              




                //if (obj is AsymmetricCipherKeyPair)
                //{
                //    privateKey = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
                //}
                //else
                //{s
                //    throw new InvalidOperationException("certificate did not have private key.");
                //}


                //                rivateKey key = null;
                //X509Certificate cert = null;
                //KeyPair keyPair = null;

                //final Reader reader = new StringReader(pem);
                //try {
                //    final PEMReader pemReader = new PEMReader(reader, new PasswordFinder() {
                //        @Override
                //        public char[] getPassword() {
                //            return password == null ? null : password.toCharArray();
                //        }
                //    });

                //    Object obj;
                //    while ((obj = pemReader.readObject()) != null) {
                //        if (obj instanceof X509Certificate) {
                //            cert = (X509Certificate) obj;
                //        } else if (obj instanceof PrivateKey) {
                //            key = (PrivateKey) obj;
                //        } else if (obj instanceof KeyPair) {
                //            keyPair = (KeyPair) obj;
                //        }
                //    }
                //} finally {
                //    reader.close();
                //}



            }

            //[TestMethod]
            //public void AlternatieSelfSignedAndRoot()
            //{
            //    var caPrivKey = Utility.GenerateCACertificate("CN=VDP Web 2");
            //    var cert = Utility.GenerateSelfSignedCertificate("CN=bitchpudding.com", "CN=VDP Web 2", caPrivKey);
            //    Utility.AddCertToStore(cert, StoreName.My, StoreLocation.CurrentUser);
            //}
        }
    }
}
