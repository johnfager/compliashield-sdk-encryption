
namespace CompliaShield.Sdk.X509Certificates
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Crypto.Prng;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using Cryptography.Encryption;
    using Cryptography.Encryption.Keys;
    using Cryptography.Utilities;

    public sealed class ProtectedX509Certificate2Generator
    {

        private X509Certificate2 _x5092;

        #region properties



        #endregion

        #region .ctors



        #endregion

        #region methods

        public async Task<ProtectedX509Certificate2> IssueNewCertificateAsync(IPublicKey keyProtector, ICertificatePolicy certificatePolicy)
        {            
            if (keyProtector == null)
            {
                throw new ArgumentNullException("keyProtectorPublicKey");
            }

            //if (keyProtector.PublicKey == null)
            //{
            //    throw new ArgumentNullException("keyProtectorPublicKey.PublicKey");
            //}

            //var publicKeyProvider = keyProtector.PublicKey.Key as RSACryptoServiceProvider;
            //if (publicKeyProvider == null)
            //{
            //    throw new NotImplementedException("keyProtectorPublicKey.PublicKey.Key must be a valid RSACryptoServiceProvider");
            //}

            string thumbprint;
            string pemPublicCert;
            byte[] pkcs12Data;

            System.Security.Cryptography.X509Certificates.X509Certificate2 x509Certificate2;

            GenerateSigningCertificate(certificatePolicy, out thumbprint, out pemPublicCert, out pkcs12Data, out x509Certificate2);

            // encrypt the password using our primary certificate

            var encryptor = new AsymmetricEncryptor() { AsymmetricStrategy = AsymmetricStrategyOption.Aes256_1000 };

            var asymEncObj = encryptor.EncryptObjectAsync(pkcs12Data, keyProtector).GetAwaiter().GetResult();
            if (string.IsNullOrEmpty(asymEncObj.KeyId) || asymEncObj.KeyId.Length != 40)
            {
                throw new InvalidOperationException("AsymmetricEncryptor.EncryptObject returned without KeyId populated.");
            }
            var protectedKey = new ProtectedX509Certificate2(x509Certificate2.Thumbprint.ToLower(), asymEncObj);
            return await Task.FromResult(protectedKey);
        }

        #endregion

        #region helpers


        private static void GenerateSigningCertificate(ICertificatePolicy certificatePolicy, out string thumbprint, out string pemPublicCert, out byte[] pkcs12Data, out System.Security.Cryptography.X509Certificates.X509Certificate2 x509Certificate2)
        {

            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var kpgen = new RsaKeyPairGenerator();
            kpgen.Init(new KeyGenerationParameters(random, 2048));
            var subjectKeyPair = kpgen.GenerateKeyPair();

            var gen = new X509V3CertificateGenerator();

            X509Name certName;
            if (certificatePolicy.X509NameDictionary == null || !certificatePolicy.X509NameDictionary.Any())
            {
                certName = new X509Name("CN=" + certificatePolicy.CommonName);
            }
            else
            {
                var list = new Dictionary<string, string>();
                AddSubjectNameItem(list, "CN", certificatePolicy.CommonName);
                foreach (var item in certificatePolicy.X509NameDictionary)
                {
                    AddSubjectNameItem(list, item.Key, item.Value);
                }
                certName = new X509Name(GetSubjectNameItemString(list));
            }

            BigInteger serialNo;
            serialNo = BigInteger.ProbablePrime(120, random);

            gen.SetSerialNumber(serialNo);
            gen.SetSubjectDN(certName);
            gen.SetIssuerDN(certName);

            gen.SetNotBefore(DateTime.UtcNow.AddHours(-2)); // go back 2 hours just to be safe
            gen.SetNotAfter(DateTime.UtcNow.AddDays(certificatePolicy.ValidForDays));
            gen.SetSignatureAlgorithm("SHA256WithRSA");
            gen.SetPublicKey(subjectKeyPair.Public);

            gen.AddExtension(
                X509Extensions.BasicConstraints.Id,
                true,
                new BasicConstraints(false));

            gen.AddExtension(X509Extensions.KeyUsage.Id,
                true,
                new KeyUsage(KeyUsage.DigitalSignature));

            // handle our key purposes
            if (!certificatePolicy.AllPurposes)
            {
                var purposes = new List<KeyPurposeID>();
                if (certificatePolicy.ServerAuthentication)
                {
                    purposes.Add(KeyPurposeID.IdKPServerAuth);
                }
                if (certificatePolicy.ClientAuthentication)
                {
                    purposes.Add(KeyPurposeID.IdKPClientAuth);
                }
                if (certificatePolicy.CodeSigning)
                {
                    purposes.Add(KeyPurposeID.IdKPCodeSigning);
                }
                if (purposes.Any())
                {
                    gen.AddExtension(
                      X509Extensions.ExtendedKeyUsage.Id,
                      true,
                      new ExtendedKeyUsage(purposes.ToArray()));
                }
            }

            var certificate = gen.Generate(subjectKeyPair.Private, random);

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
            {
                throw new PemException("Malformed sequence in RSA private key.");
            }

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            // this is exportable to get the bytes of the key to our file system in an encrypted manner
            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaparams);
            CspParameters cspParameters = new CspParameters();
            cspParameters.KeyContainerName = Guid.NewGuid().ToString();
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(2048, cspParameters);
            rsaKey.PersistKeyInCsp = false; // do not persist          
            rsaKey.ImportParameters(rsaParameters);

            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());
            x509.PrivateKey = rsaKey;

            // this is non-exportable
            CspParameters cspParametersNoExport = new CspParameters();
            cspParametersNoExport.KeyContainerName = Guid.NewGuid().ToString();
            cspParametersNoExport.Flags = CspProviderFlags.UseNonExportableKey;
            RSACryptoServiceProvider rsaKey2 = new RSACryptoServiceProvider(2048, cspParametersNoExport);
            rsaKey2.PersistKeyInCsp = false; // do not persist   
            rsaKey2.ImportParameters(rsaParameters);

            x509Certificate2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());
            x509Certificate2.PrivateKey = rsaKey2;

            //// Generating Random Numbers
            //var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-()#$%^&@+=!";
            //var rnd = new Random();

            //password = new string(
            //    Enumerable.Repeat(chars, 15)
            //              .Select(s => s[rnd.Next(s.Length)])
            //              .ToArray());

            thumbprint = x509.Thumbprint.ToLower();

            var publicKeyPem = new StringBuilder();
            var utf8WithoutBom = new System.Text.UTF8Encoding(false);
            var publicKeyPemWriter = new PemWriter(new StringWriterWithEncoding(publicKeyPem, utf8WithoutBom));
            publicKeyPemWriter.WriteObject(certificate);
            publicKeyPemWriter.Writer.Flush();
            pemPublicCert = publicKeyPem.ToString();
            pemPublicCert = pemPublicCert.Replace(Environment.NewLine, "\n"); //only use newline and not returns

            pkcs12Data = x509.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx);
        }

        private static void AddSubjectNameItem(Dictionary<string, string> dic, string key, string value)
        {
            dic[key] = value.Replace(",", @"\,");
        }

        private static string GetSubjectNameItemString(Dictionary<string, string> dic)
        {
            var rev = dic.Reverse();

            var sb = new StringBuilder();
            foreach (var item in rev)
            {
                sb.Append(item.Key + "=" + item.Value + ",");
            }
            sb.Length--;
            return sb.ToString();
        }


        #endregion

    }
}
