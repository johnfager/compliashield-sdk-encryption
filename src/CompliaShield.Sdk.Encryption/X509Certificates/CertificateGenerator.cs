
namespace CompliaShield.Security.Cryptography.X509Certificates
{
    using System;
    using System.Collections;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
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
    using Org.BouncyCastle.X509.Extension;


    public class CertificateGenerator
    {

        public static void GenerateRootCertificate(string subjectName, DateTime expireOnUtc, out string password, out string pemValue, out byte[] cerData, out byte[] pkcs12Data)
        {

            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var kpgen = new RsaKeyPairGenerator();
            kpgen.Init(new KeyGenerationParameters(random, 2048)); 
            var subjectKeyPair = kpgen.GenerateKeyPair();

            var gen = new X509V3CertificateGenerator();

            var certName = new X509Name("CN=" + subjectName);
            BigInteger serialNo = BigInteger.ProbablePrime(120, random);
            gen.SetSerialNumber(serialNo);

            gen.SetSubjectDN(certName);
            gen.SetIssuerDN(certName);

            gen.SetNotAfter(expireOnUtc);
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            gen.SetSignatureAlgorithm("SHA256WithRSA");
            gen.SetPublicKey(subjectKeyPair.Public);

            var certificate = gen.Generate(subjectKeyPair.Private, random);

            var privateKeyPem = new StringBuilder();
            var privateKeyPemWriter = new PemWriter(new StringWriter(privateKeyPem));

            privateKeyPemWriter.WriteObject(certificate);
            privateKeyPemWriter.WriteObject(subjectKeyPair.Private);
            privateKeyPemWriter.Writer.Flush();
            pemValue = privateKeyPem.ToString();

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);
            var x509 = X509CertificateHelper.GetCertificate(certificate.GetEncoded(), null, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
            {
                throw new PemException("Malformed sequence in RSA private key.");
            }

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaparams);
            CspParameters cspParameters = new CspParameters();
            cspParameters.KeyContainerName = Guid.NewGuid().ToString(); // "MyKeyContainer";
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(2048, cspParameters);
            rsaKey.ImportParameters(rsaParameters);

            x509.PrivateKey = rsaKey; 

            // Generating Random Numbers
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-()#$%^&@+=!";
            var rnd = new Random();

            var result = new string(
                Enumerable.Repeat(chars, 15)
                          .Select(s => s[rnd.Next(s.Length)])
                          .ToArray());
            password = result;

            cerData = x509.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
            pkcs12Data = x509.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pfx, password);

        }

        /// <summary>
        /// 
        /// </summary>
        /// <remarks>Based on <see cref="http://www.fkollmann.de/v2/post/Creating-certificates-using-BouncyCastle.aspx"/></remarks>
        /// <param name="subjectName"></param>
        /// <returns></returns>
        public static void GenerateCertificate(string subjectName, DateTime expireOnUtc, byte[] issuingCertificate, string issuingCertificatePassword, out string password, out byte[] cerData, out byte[] pkcs12Data)
        {

            AsymmetricKeyParameter caPrivateKey;
            var caCert = ReadCertificateFromBytes(issuingCertificate, issuingCertificatePassword, out caPrivateKey);

            var caAuth = new AuthorityKeyIdentifierStructure(caCert);
            var authKeyId = new AuthorityKeyIdentifier(caAuth.GetKeyIdentifier());

            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-()#$%^&@+=!";
            var rnd = new Random();
            var result = new string(
                Enumerable.Repeat(chars, 15)
                          .Select(s => s[rnd.Next(s.Length)])
                          .ToArray());
            password = result;

            var gen = new X509V3CertificateGenerator();
            var certName = new X509Name("CN=" + subjectName);
            var serialNo = BigInteger.ProbablePrime(120, random);
            gen.SetSerialNumber(serialNo);
            gen.SetSubjectDN(certName);
            gen.SetIssuerDN(caCert.IssuerDN);

            // gen.SetIssuerUniqueID(caCert.IssuerUniqueID.GetBytes())

            gen.SetNotAfter(expireOnUtc);
            gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            gen.SetSignatureAlgorithm("SHA256WithRSA"); //("MD5WithRSA");

            var kpgen = new RsaKeyPairGenerator();
            kpgen.Init(new KeyGenerationParameters(random, 2048)); // new SecureRandom(new CryptoApiRandomGenerator()), 2048));
            var subjectKeyPair = kpgen.GenerateKeyPair();
            gen.SetPublicKey(subjectKeyPair.Public);

            //gen.AddExtension(
            //    X509Extensions.ExtendedKeyUsage.Id,
            //    false,
            //    new ExtendedKeyUsage(new KeyPurposeID[] { KeyPurposeID.IdKPClientAuth, KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPCodeSigning }));

            //1.3.6.1.5.5.7.3.1 = server authentication
            //1.3.6.1.5.5.7.3.2 = client authentication
            //1.3.6.1.5.5.7.3.3 = code signing

            var certificate = gen.Generate(caPrivateKey);

            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            // merge into X509Certificate2
            var x509 = X509CertificateHelper.GetCertificate(certificate.GetEncoded(), null, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.PrivateKey.GetDerEncoded());
            if (seq.Count != 9)
            {
                throw new PemException("Malformed sequence in RSA private key.");
            }

            var rsa = new RsaPrivateKeyStructure(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            RSAParameters rsaParameters = DotNetUtilities.ToRSAParameters(rsaparams);
            CspParameters cspParameters = new CspParameters();
            cspParameters.KeyContainerName = Guid.NewGuid().ToString(); // "MyKeyContainer";
            RSACryptoServiceProvider rsaKey = new RSACryptoServiceProvider(2048, cspParameters);
            rsaKey.ImportParameters(rsaParameters);

            x509.PrivateKey = rsaKey; 
            cerData = x509.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert);
            pkcs12Data = x509.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, password);
        }

        private byte[] gen()
        {
            TextReader textReader = new StreamReader("certificaterequest.pkcs10");
            PemReader pemReader = new PemReader(textReader);

            Pkcs10CertificationRequest certificationRequest = (Pkcs10CertificationRequest)pemReader.ReadObject();
            CertificationRequestInfo certificationRequestInfo = certificationRequest.GetCertificationRequestInfo();
            SubjectPublicKeyInfo publicKeyInfo = certificationRequestInfo.SubjectPublicKeyInfo;

            RsaPublicKeyStructure publicKeyStructure = RsaPublicKeyStructure.GetInstance(publicKeyInfo.GetPublicKey());

            RsaKeyParameters publicKey = new RsaKeyParameters(false, publicKeyStructure.Modulus, publicKeyStructure.PublicExponent);

            bool certIsOK = certificationRequest.Verify(publicKey);
            // public key is OK here...

            // get the server certificate
            Org.BouncyCastle.X509.X509Certificate serverCertificate = DotNetUtilities.FromX509Certificate(System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromCertFile("servermastercertificate.cer"));

            // get the server private key
            byte[] privateKeyBytes = File.ReadAllBytes("serverprivate.key");

            AsymmetricKeyParameter serverPrivateKey = PrivateKeyFactory.CreateKey(privateKeyBytes);

            // generate the client certificate
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();

            generator.SetSerialNumber(BigInteger.ProbablePrime(120, new Random()));
            generator.SetIssuerDN(serverCertificate.SubjectDN);
            generator.SetNotBefore(DateTime.Now);
            generator.SetNotAfter(DateTime.Now.AddYears(5));
            generator.SetSubjectDN(certificationRequestInfo.Subject);
            generator.SetPublicKey(publicKey);
            generator.SetSignatureAlgorithm("SHA512withRSA");
            generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(serverCertificate));
            generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));

            var newClientCert = generator.Generate(serverPrivateKey);

            newClientCert.Verify(publicKey); // <-- this blows up

            return DotNetUtilities.ToX509Certificate(newClientCert).Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, "user password");

        }


        public static AsymmetricAlgorithm ToDotNetKey(RsaPrivateCrtKeyParameters privateKey)
        {
            var cspParams = new CspParameters
            {
                KeyContainerName = Guid.NewGuid().ToString(),
                KeyNumber = (int)KeyNumber.Exchange,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            var rsaProvider = new RSACryptoServiceProvider(cspParams);
            return rsaProvider;
        }

        public static AsymmetricKeyParameter TransformRSAPrivateKey(AsymmetricAlgorithm privateKey)
        {
            RSACryptoServiceProvider prov = privateKey as RSACryptoServiceProvider;
            RSAParameters parameters = prov.ExportParameters(true);

            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, parameters.Modulus),
                new BigInteger(1, parameters.Exponent),
                new BigInteger(1, parameters.D),
                new BigInteger(1, parameters.P),
                new BigInteger(1, parameters.Q),
                new BigInteger(1, parameters.DP),
                new BigInteger(1, parameters.DQ),
                new BigInteger(1, parameters.InverseQ));
        }

        public static X509Certificate ReadCertificateFromBytes(byte[] certificate, string password, out AsymmetricKeyParameter privateKey)
        {
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate, password, System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            
            privateKey = TransformRSAPrivateKey(x509.PrivateKey);

            var cert = DotNetUtilities.FromX509Certificate(x509);
            return cert;
        }

        public static RsaPrivateCrtKeyParameters GetPrivateKey(string pemFile)
        {
            if (string.IsNullOrEmpty(pemFile)) throw new ArgumentNullException("pemFile");

            string privateKey = File.Exists(pemFile) ? File.ReadAllText(pemFile) : pemFile;

            var reader = new PemReader(new StringReader(privateKey));
            RsaPrivateCrtKeyParameters privkey = null;
            Object obj = reader.ReadObject();
            if (obj is AsymmetricCipherKeyPair)
            {
                privkey = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)obj).Private;
            }
            return privkey;
        }


        // This reads a certificate from a file.
        // Thanks to: http://blog.softwarecodehelp.com/2009/06/23/CodeForRetrievePublicKeyFromCertificateAndEncryptUsingCertificatePublicKeyForBothJavaC.aspx
        public static X509Certificate ReadCertFromFile(string certificatePath, string password, out AsymmetricKeyParameter privateKey)
        {
            var x5092 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificatePath, password);
            var cert = DotNetUtilities.FromX509Certificate(x5092);
            privateKey = TransformRSAPrivateKey(x5092.PrivateKey);
            return cert;
        }
    }
}
