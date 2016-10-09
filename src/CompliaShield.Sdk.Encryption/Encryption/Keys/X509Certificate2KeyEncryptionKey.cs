
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using Extensions;
    using Hashing;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Utilities;

    public sealed class X509Certificate2KeyEncryptionKey : X509CertificatePublicKey, IPrivateKey
    {

        #region .ctors

        public X509Certificate2KeyEncryptionKey(X509Certificate2 x509Certificate2) : base(x509Certificate2)
        {
            // base handles lots of the validation
            if (!x509Certificate2.HasPrivateKey)
            {
                throw new ArgumentException(string.Format("x509Certificate2 with thumbprint '{0}' does not have a private key.", x509Certificate2.Thumbprint));
            }

            var badPrivateKeyEx = new ArgumentException(string.Format("x509Certificate2 with thumbprint '{0}' does not have a private key.", x509Certificate2.Thumbprint));

            try
            {
                if (x509Certificate2.PrivateKey == null)
                {
                    throw badPrivateKeyEx;
                }
            }
            catch (Exception ex)
            {
                if (ex == badPrivateKeyEx)
                {
                    throw;
                }
                throw new ArgumentException(badPrivateKeyEx.Message, ex);
            }
            _x5092 = x509Certificate2;
        }

        #endregion

        public async Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm)
        {
            return await this.SignAsync(digest, algorithm, CancellationToken.None);
        }

        /// <summary>
        /// Signs a byte array by creating an appropriate hash.
        /// </summary>
        /// <param name="digest">Any data to sign.</param>
        /// <param name="algorithm">MD5 or SHA1</param>
        /// <param name="token"></param>
        /// <returns>The signature for the digest as a byte array and string based hash code.</returns>
        public async Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm, CancellationToken token)
        {
            this.EnsureUsable();

            if (digest == null || !digest.Any())
            {
                throw new ArgumentException("digest");
            }
            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }
            var crypto = this.GetRSACryptoServiceProvider();
            var signer = new Signing.Signer(crypto);
            //var hash = BasicHasher.GetHash(digest, algorithm);
            return await Task.FromResult(signer.SignHash(digest, algorithm));
        }

        public async Task<Tuple<byte[], string>> SignAsync(string hex)
        {
            this.EnsureUsable();
            var crypto = this.GetRSACryptoServiceProvider();
            var signer = new Signing.Signer(crypto);
            var algorithm = BasicHasher.GetNormalAlgorithm(hex);
            return await Task.FromResult(signer.SignHash(hex, algorithm));
        }

        public async Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey)
        {
            return await this.UnwrapKeyAsync(encryptedKey, CancellationToken.None);
        }

        public async Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey, CancellationToken token)
        {
            this.EnsureUsable();

            var algorithm = this.GetRSACryptoServiceProvider();
            byte[] keyOut;
            try
            {
                keyOut = await Task.FromResult(algorithm.Decrypt(encryptedKey, false));
            }
            catch (Exception ex)
            {
                throw new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' throw an exception on Decrypt. See inner exception for details", _x5092.Thumbprint), ex);
            }
            return keyOut;
        }

        #region helpers

        private RSACryptoServiceProvider GetPublicRSACryptoServiceProvider()
        {
            RSACryptoServiceProvider alg = null;
            if (_x5092.PublicKey != null)
            {
                alg = _x5092.PublicKey.Key as RSACryptoServiceProvider;
            }
            if (alg == null)
            {
                throw new NotImplementedException(string.Format("X509Certificate2 with thumbprint '{0}' PublicKey.Key is not a valid RSACryptoServiceProvider.", _x5092.Thumbprint));
            }
            return alg;
        }

        private RSACryptoServiceProvider GetRSACryptoServiceProvider()
        {
            var alg = _x5092.PrivateKey as RSACryptoServiceProvider;
            if (alg == null)
            {
                throw new NotImplementedException(string.Format("X509Certificate2 with thumbprint '{0}' PrivateKey is not a valid RSACryptoServiceProvider. PrivateKey is of type '{1}'.", _x5092.Thumbprint, _x5092.PrivateKey.GetType().FullName));
            }
            return alg;
        }

        #endregion
    }
}
