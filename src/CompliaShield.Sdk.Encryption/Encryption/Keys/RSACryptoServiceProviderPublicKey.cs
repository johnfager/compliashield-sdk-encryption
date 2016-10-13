
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


    public class RSACryptoServiceProviderPublicKey
    {

        protected RSACryptoServiceProvider _rsa;


        public virtual string KeyLocator { get; set; }

        public virtual string Actor { get; set; }

        public virtual string KeyId { get; protected set; }

        public virtual DateTime NotBefore { get; protected set; }

        public virtual DateTime NotAfter { get; protected set; }

        public virtual bool Disabled { get; protected set; }

        #region .ctors

        public RSACryptoServiceProviderPublicKey(RSACryptoServiceProvider rsa, string keyLocator, string keyId, DateTime? notBefore = null, DateTime? notAfter = null, bool disabled = false)
        {
            if (rsa == null)
            {
                throw new ArgumentNullException(nameof(rsa));
            }
            if(string.IsNullOrEmpty(keyLocator))
            {
                throw new ArgumentException(nameof(keyLocator));
            }
            if(string.IsNullOrEmpty(KeyId))
            {
                throw new ArgumentException(nameof(keyId));
            }
            
            _rsa = rsa;
            this.KeyLocator = KeyLocator;
            this.KeyId = KeyId;
            if(notBefore.HasValue)
            {
                this.NotBefore = notBefore.Value;
            }
            else
            {
                this.NotBefore = DateTime.MinValue;
            }
            if (notAfter.HasValue)
            {
                this.NotBefore = notBefore.Value;
            }
            else
            {
                this.NotBefore = DateTime.MinValue;
            }
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

            var verifier = new Signing.Verifier(_rsa);
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
            var verifier = new Signing.Verifier(_rsa);

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
            var verifier = new Signing.Verifier(_rsa);
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
            if (key == null || !key.Any())
            {
                throw new ArgumentNullException(nameof(key));
            }
            this.EnsureUsable();
            var encrypted = await Task.FromResult(_rsa.Encrypt(key, false));
            return encrypted;
        }

        public string PublicKeyToPEM()
        {
            this.EnsureUsable();
            return RSACryptoServiceProviderHelper.ExportPublicKey(_rsa);
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

        #endregion

    }
}
