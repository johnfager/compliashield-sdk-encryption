
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

    public sealed class X509Certificate2KeyEncryptionKey : IKeyEncyrptionKey
    {

        private X509Certificate2 _x5092;

        private bool _isDisposed;

        public bool IsDisposed { get { return _isDisposed; } }

        public string Actor { get; set; }

        public string KeyId { get; private set; }

        public DateTime NotBefore
        {
            get
            {
                if (_x5092 == null)
                {
                    // max value means it should not be used
                    return DateTime.MaxValue;
                }
                return _x5092.NotBefore;
            }
        }

        public DateTime NotAfter
        {
            get
            {
                if (_x5092 == null)
                {
                    // min value means it should not be used
                    return DateTime.MinValue;
                }
                return _x5092.NotAfter;
            }
        }

        public PublicKey PublicKey
        {
            get
            {
                this.EnsureNotDisposed();
                return _x5092.PublicKey;
            }
        }

        #region .ctors

        public X509Certificate2KeyEncryptionKey(X509Certificate2 x509Certificate2)
        {
            if (x509Certificate2 == null)
            {
                throw new ArgumentException("x509Certificate2");
            }
            if (x509Certificate2.Thumbprint != null)
            {
                this.KeyId = x509Certificate2.Thumbprint.ToLower();
            }
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
            this.EnsureNotDisposed();

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
            this.EnsureNotDisposed();
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
            this.EnsureNotDisposed();

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

        public async Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm)
        {
            return await this.VerifyAsync(digest, signature, algorithm, CancellationToken.None);
        }

        /// <summary>
        /// Verifies the byte array against a signature.
        /// </summary>
        /// <param name="digest"></param>
        /// <param name="signature"></param>
        /// <param name="algorithm"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        public async Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm, CancellationToken token)
        {
            this.EnsureNotDisposed();
            if (digest == null || !digest.Any())
            {
                throw new ArgumentException("digest");
            }
            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            var verifier = new Signing.Verifier(this.GetPublicRSACryptoServiceProvider());
            //var hash = BasicHasher.GetHash(digest, algorithm);
            return await Task.FromResult(verifier.VerifyHash(digest, signature, algorithm));
        }

        public async Task<bool> VerifyAsync(byte[] digest, string signature, string algorithm)
        {
            return await this.VerifyAsync(digest, signature, algorithm, CancellationToken.None);
        }

        public async Task<bool> VerifyAsync(byte[] digest, string signature, string algorithm, CancellationToken token)
        {
            this.EnsureNotDisposed();
            if (digest == null || !digest.Any())
            {
                throw new ArgumentException("digest");
            }
            BasicHasher.ValidateDigestLength(algorithm, digest);
            var verifier = new Signing.Verifier(this.GetPublicRSACryptoServiceProvider());

            var hex = digest.ToHexString();
            var res = await Task.FromResult(verifier.VerifyHash(hex, signature, algorithm));

            //var res = await Task.FromResult(verifier.VerifyHash(digest, signature, algorithm));

            if (!res)
            {
                // legacy code used a double digest hash, so hash once more and check
                var hashBytesLegacy = BasicHasher.GetHashBytes(digest, algorithm);
                res = await Task.FromResult(verifier.VerifyHash(digest, signature, algorithm));
                return res;
            }
            return res;
        }

        public async Task<bool> VerifyAsync(string hex, string signature)
        {
            return await this.VerifyAsync(hex, signature, CancellationToken.None);
        }

        public async Task<bool> VerifyAsync(string hex, string signature, CancellationToken token)
        {
            this.EnsureNotDisposed();
            string algorithm = BasicHasher.GetNormalAlgorithm(hex);
            var verifier = new Signing.Verifier(this.GetPublicRSACryptoServiceProvider());
            var res = await Task.FromResult(verifier.VerifyHash(hex, signature, algorithm));
            if (!res)
            {
                // legacy code used a double digest hash, so hash once more and check
                var hashHexLegacy = BasicHasher.GetHash(hex, algorithm);
                res = await Task.FromResult(verifier.VerifyHash(hashHexLegacy, signature, algorithm));
                return res;
            }
            return res;
        }

        public async Task<byte[]> WrapKeyAsync(byte[] key)
        {
            return await this.WrapKeyAsync(key, CancellationToken.None);
        }

        public async Task<byte[]> WrapKeyAsync(byte[] key, CancellationToken token)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }
            //if (algorithm == null)
            //{
            //    throw new ArgumentNullException(nameof(algorithm));
            //}

            this.EnsureNotDisposed();
            if (this.PublicKey == null)
            {
                throw new InvalidOperationException("There is no PublicKey");
            }

            var fOAEP = false;
            var rsa = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(_x5092);
            var encrypted = await Task.FromResult(rsa.Encrypt(key, fOAEP));
            return encrypted;
            //var encryptedAsString = Encoding.UTF8.GetString(encrypted);
            //return new Tuple<byte[], string>(encrypted, encryptedAsString);
        }

        public string PublicKeyToPEM()
        {
            this.EnsureNotDisposed();
            return X509CertificateHelper.ExportToPEM(_x5092);
        }

        public void Dispose()
        {
            _isDisposed = true;
        }

        #region helpers

        private void EnsureNotDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
        }

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
