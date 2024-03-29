
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.OpenSsl;
    using Org.BouncyCastle.Security;
    using Encryption.Keys;

    public static class X509CertificateHelper
    {

        public static IPrivateKey GetKeyEncryptionKey(X509Certificate2 x509Certificate2)
        {
            return new X509Certificate2KeyEncryptionKey(x509Certificate2);
        }

        public static IPublicKey GetPublicKey(X509Certificate2 x509Certificate2)
        {
            return new X509CertificatePublicKey(x509Certificate2);
        }

        public static RSACryptoServiceProvider GetRSACryptoServiceProviderFromPrivateKey(X509Certificate2 x509Certificate2)
        {
            if (x509Certificate2 == null)
            {
                throw new ArgumentException("x509Certificate2");
            }
            if (!x509Certificate2.HasPrivateKey)
            {
                throw new InvalidOperationException(string.Format("X509Certificate2 with thumbprint '{0}' does not have a private key.", x509Certificate2.Thumbprint.ToLower()));
            }
            try
            {
                var rsa = x509Certificate2.PrivateKey as RSACryptoServiceProvider;
                if (rsa != null)
                {
                    return rsa;
                }
            }
            catch (Exception ex)
            {
                var outerEx = new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' indicates that HasPrivateKey is TRUE, but the service or account may not have access to the private key or the private key may be missing or corrupted.", x509Certificate2.Thumbprint.ToLower()), ex);
                throw outerEx;
            }
            // if to here there is a problem
            throw new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' indicates that HasPrivateKey is TRUE, but the service or account may not have access to the private key or the private key may be missing or corrupted.", x509Certificate2.Thumbprint.ToLower()));
        }

        public static RSACryptoServiceProvider GetRSACryptoServiceProviderFromPublicKey(X509Certificate2 x509Certificate2)
        {
            if (x509Certificate2 == null)
            {
                throw new ArgumentException("x509Certificate2");
            }
            if (x509Certificate2.PublicKey == null)
            {
                throw new ArgumentException("x509Certificate2.PublicKey.Key must be populated.");
            }

            try
            {
                var rsa = x509Certificate2.PublicKey.Key as RSACryptoServiceProvider;
                if (rsa != null)
                {
                    return rsa;
                }
            }
            catch (Exception ex)
            {
                var outerEx = new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' indicates that HasPrivateKey is TRUE, but the service or account may not have access to the private key or the private key may be missing or corrupted.", x509Certificate2.Thumbprint.ToLower()), ex);
                throw outerEx;
            }
            throw new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' does not have a valid RSA public key.", x509Certificate2.Thumbprint.ToLower()));
        }


        //public static RSACryptoServiceProvider GetRSACryptoServiceProviderFromPublicKey(IPublicKey publicKey)
        //{
        //    if (publicKey == null)
        //    {
        //        throw new ArgumentNullException(nameof(publicKey));
        //    }
          
        //    if (publicKey.PublicKey == null)
        //    {
        //        throw new ArgumentException("publicKey.PublicKey.Key must be populated.");
        //    }

        //    try
        //    {
        //        var rsa = publicKey.PublicKey.Key as RSACryptoServiceProvider;
        //        if (rsa != null)
        //        {
        //            return rsa;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        var outerEx = new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' indicates that HasPrivateKey is TRUE, but the service or account may not have access to the private key or the private key may be missing or corrupted.", publicKey.KeyId), ex);
        //        throw outerEx;
        //    }
        //    throw new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' does not have a valid RSA public key.", publicKey.KeyId));
        //}


        public static RSACryptoServiceProvider GetRSACryptoServiceProviderFromPublicKey(string publicKeyPem)
        {
            if (string.IsNullOrEmpty(publicKeyPem))
            {
                throw new ArgumentException("publicKeyPem must have a value");
            }

            RSACryptoServiceProvider rsa;
            using (var keyreader = new StringReader(publicKeyPem))
            {
                var pemReader = new PemReader(keyreader);
                var cert = (Org.BouncyCastle.X509.X509Certificate)pemReader.ReadObject();

                var asymmetricKeyParameter = cert.GetPublicKey();
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
                rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);

                //using (var rsaProvider = new RSACryptoServiceProvider(Convert.ToInt32(cert.), cspParams))
                //{
                //    try
                //    {
                //        // Read public key from file
                //        publicKeyText = System.Text.Encoding.UTF8.GetString(publicKey);

                //        // Import public key
                //        rsaProvider.FromXmlString(publicKeyText);
                //    }

                //    var param = Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(cert.GetPublicKey )  // .Pvate;

                //    var y = (RsaKeyParameters)cert.GetKeyAlgorithmParameters();
                //    rsa = (RSACryptoServiceProvider)RSACryptoServiceProvider.Create();
                //    var rsaParameters = new RSAParameters();
                //    rsaParameters.Modulus = y.Modulus.ToByteArray();
                //    rsaParameters.Exponent = y.Exponent.ToByteArray();
                //    rsa.ImportParameters(rsaParameters);
            }
            return rsa;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="base64EncodedString">Cannot include BEGIN CERTIFICATE!!!</param>
        /// <returns></returns>
        public static RSACryptoServiceProvider GetRSACryptoServiceProviderFromBase64String(string base64EncodedString)
        {
            byte[] publicKeyBytes;

            publicKeyBytes = Convert.FromBase64String(base64EncodedString);
            var asymmetricKeyParameter = PublicKeyFactory.CreateKey(publicKeyBytes);
            var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            var rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        /// <summary>
        /// Export a certificate to a PEM format string
        /// </summary>
        /// <param name="cert">The certificate to export</param>
        /// <returns>A PEM encoded string</returns>
        public static string ExportToPEM(X509Certificate cert)
        {
            var builder = new StringBuilder();
            builder.AppendLine("-----BEGIN CERTIFICATE-----");
            var bytes = cert.Export(X509ContentType.Cert);
            builder.AppendLine(Convert.ToBase64String(bytes, Base64FormattingOptions.InsertLineBreaks));
            builder.AppendLine("-----END CERTIFICATE-----");
            var output = builder.ToString();
            // just a single newline
            output = output.Replace(Environment.NewLine, "\n");
            return output;
        }

        public static string ExportToPublicSshKey(X509Certificate2 cert)
        {
            if (cert == null)
            {
                throw new ArgumentException(nameof(cert));
            }
            try
            {
                return ExportToSshKey(GetRSACryptoServiceProviderFromPublicKey(cert), false);
            }
            catch (Exception ex)
            {
                var outer = new CryptoException(string.Format("Could not ExportToPrivateSshKey; Tumbprint '{0}'. See inner exception for details.", cert.Thumbprint), ex);
                throw outer;
            }
        }


        public static string ExportToPrivateSshKey(X509Certificate2 cert)
        {
            if (cert == null)
            {
                throw new ArgumentException(nameof(cert));
            }
            if (!cert.HasPrivateKey)
            {
                throw new CryptoException(string.Format("Could not ExportToPrivateSshKey; Tumbprint '{0}' does not have a private key. See inner exception for details.", cert.Thumbprint));
            }
            try
            {
                return ExportToSshKey(GetRSACryptoServiceProviderFromPrivateKey(cert), true);
            }
            catch (Exception ex)
            {
                var outer = new CryptoException(string.Format("Could not ExportToPrivateSshKey; Tumbprint '{0}'. See inner exception for details.", cert.Thumbprint), ex);
                throw outer;
            }
        }

        public static string ExportToSshKey(RSACryptoServiceProvider crytpo, bool includePrivateParameters)
        {
            if (crytpo == null)
            {
                throw new ArgumentNullException("crypto");
            }

            RSAParameters parameters = crytpo.ExportParameters(false);

            RsaKeyParameters r = DotNetUtilities.GetRsaPublicKey(parameters);

            byte[] sshrsa_bytes = Encoding.Default.GetBytes("ssh-rsa");
            byte[] n = r.Modulus.ToByteArray();
            byte[] e = r.Exponent.ToByteArray();

            string buffer64;
            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(ToBytes(sshrsa_bytes.Length), 0, 4);
                ms.Write(sshrsa_bytes, 0, sshrsa_bytes.Length);
                ms.Write(ToBytes(e.Length), 0, 4);
                ms.Write(e, 0, e.Length);
                ms.Write(ToBytes(n.Length), 0, 4);
                ms.Write(n, 0, n.Length);
                ms.Flush();
                buffer64 = Convert.ToBase64String(ms.ToArray());
            }

            var publicSsh = string.Format("ssh-rsa {0}", buffer64);
            return publicSsh;
        }

        private static byte[] ToBytes(int i)
        {
            byte[] bts = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bts);
            }
            return bts;
        }

    }
}
