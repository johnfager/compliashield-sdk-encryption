
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using Utilities;

    public partial class X509Certificate2KeyEncryptionKey : IKeyEncyrptionKey
    {

        private X509Certificate2 _x5092;

        private bool _isDisposed;

        public string KeyId { get; private set; }

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
            return await this.SignAsync(digest, algorithm, new CancellationToken());
        }

        public async Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm, CancellationToken token)
        {
            this.EnsureNotDisposed();

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            var signer = new Signing.Signer(this.GetRSACryptoServiceProvider());

            algorithm = algorithm.ToLower();
            switch (algorithm)
            {
                case "md5":
                    return await Task.FromResult(signer.SignMd5(digest));
                case "sha1":
                    return await Task.FromResult(signer.SignSha1(digest));
                default:
                    throw new NotImplementedException(string.Format("algorithm '{0}' is not implemented.", algorithm));
            }
        }

        public async Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey)
        {
            return await this.UnwrapKeyAsync(encryptedKey, new CancellationToken());
        }

        public async Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey, CancellationToken token)
        {
            this.EnsureNotDisposed();

            var alg = this.GetRSACryptoServiceProvider();
            byte[] keyOut;
            try
            {
                keyOut = alg.Decrypt(encryptedKey, false);
            }
            catch (Exception ex)
            {
                throw new CryptographicException(string.Format("X509Certificate2 with thumbprint '{0}' throw an exception on Decrypt. See inner exception for details", _x5092.Thumbprint), ex);
            }
            return await Task.FromResult(keyOut);
        }

        public async Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm)
        {
            return await this.VerifyAsync(digest, signature, algorithm, new CancellationToken());
        }

        public async Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm, CancellationToken token)
        {
            this.EnsureNotDisposed();

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            var verifier = new Signing.Verifier(this.GetRSACryptoServiceProvider());

            algorithm = algorithm.ToLower();
            switch (algorithm)
            {
                case "md5":
                    return await Task.FromResult(verifier.VerifyMd5Hash(digest, signature));
                case "sha1":
                    return await Task.FromResult(verifier.VerifySha1Hash(digest, signature));
                default:
                    throw new NotImplementedException(string.Format("algorithm '{0}' is not implemented.", algorithm));
            }
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
