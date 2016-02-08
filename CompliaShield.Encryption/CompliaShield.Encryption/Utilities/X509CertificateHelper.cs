
namespace CompliaShield.Encryption.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    public static class X509CertificateHelper
    {
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

    }
}
