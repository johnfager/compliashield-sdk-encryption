
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

    public partial class X509CertificatePublicKey : IPublicKey
    {

        protected X509Certificate2 _x5092;


        public virtual string KeyLocator { get; set; }

        public virtual string Actor { get; set; }

        public virtual string KeyId { get; protected set; }

        public virtual DateTime NotBefore
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

        public virtual DateTime NotAfter
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

        public virtual PublicKey PublicKey
        {
            get
            {
                this.EnsureNotDisposed();
                return _x5092.PublicKey;
            }
        }

        public virtual bool Disabled { get; protected set; }

        #region .ctors

        public X509CertificatePublicKey(X509Certificate2 x509Certificate2)
        {
            if (x509Certificate2 == null)
            {
                throw new ArgumentException("x509Certificate2");
            }
            if (x509Certificate2.Thumbprint != null)
            {
                this.KeyId = x509Certificate2.Thumbprint.ToLower();
            }
            if (x509Certificate2.PublicKey == null)
            {
                throw new ArgumentException("x509Certificate2.PublicKey");
            }
            _x5092 = x509Certificate2;
        }
        
        protected bool _isDisposed;

        public virtual bool IsDisposed { get { return _isDisposed; } }

        #endregion


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

            this.EnsureUsable();
            if (this.PublicKey == null)
            {
                throw new InvalidOperationException("There is no PublicKey");
            }

            if (this.NotAfter < DateTime.UtcNow)
            {
                throw new EncryptionException($"Operation is not allowed on expired key; Key '{this.Actor}/{this.KeyId}'.");
            }

            var fOAEP = true; // changed to more modern standard 2017/05/08
            var rsa = X509CertificateHelper.GetRSACryptoServiceProviderFromPublicKey(_x5092);
            var encrypted = await Task.FromResult(rsa.Encrypt(key, fOAEP));
            return encrypted;
            //var encryptedAsString = Encoding.UTF8.GetString(encrypted);
            //return new Tuple<byte[], string>(encrypted, encryptedAsString);
        }

        public string PublicKeyToPEM()
        {
            this.EnsureUsable();
            return X509CertificateHelper.ExportToPEM(_x5092);
        }

        public virtual void Dispose()
        {
            _isDisposed = true;
        }

        #region helpers

        protected virtual void EnsureNotDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
        }

        protected virtual void EnsureUsable()
        {
            this.EnsureNotDisposed();
            if (this.Disabled)
            {
                throw new InvalidOperationException(string.Format("Key '{0}' is disabled.", this.KeyId));
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

        #endregion

    }
}
