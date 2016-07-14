
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Extensions;

    public sealed class ProtectedX509Certificate2 : IProtectedKey
    {

        private bool _isDisposed;

        private AsymmetricallyEncryptedObject _encryptedKey;

        #region properties

        public string KeyId { get; private set; }

        #endregion

        #region .ctors

        public ProtectedX509Certificate2(string keyId, byte[] keyAsBytes)
        {
            if (keyAsBytes == null)
            {
                throw new ArgumentNullException("keyAsBytes");
            }
            var encryptedKey = new AsymmetricallyEncryptedObject();
            encryptedKey.LoadFromByteArray(keyAsBytes);
            if (!string.IsNullOrEmpty(encryptedKey.Key2Id))
            {
                throw new NotImplementedException(string.Format("encryptedKey has a value of '{0}' on Key2Id. Dual key encryption is not supported on IProtectedKey implementations.", encryptedKey.Key2Id));
            }
            if (keyId == null)
            {
                throw new ArgumentNullException("keyId");
            }
            if (keyId.Length != 40)
            {
                throw new ArgumentNullException("keyId must be 40 characters");
            }
            this.KeyId = keyId;
            _encryptedKey = encryptedKey;
        }

        public ProtectedX509Certificate2(string keyId, AsymmetricallyEncryptedObject encryptedKey)
        {
            if (encryptedKey == null)
            {
                throw new ArgumentNullException("encryptedKey");
            }
            if (!string.IsNullOrEmpty(encryptedKey.Key2Id))
            {
                throw new NotImplementedException(string.Format("encryptedKey has a value of '{0}' on Key2Id. Dual key encryption is not supported on IProtectedKey implementations.", encryptedKey.Key2Id));
            }
            if (keyId == null)
            {
                throw new ArgumentNullException("keyId");
            }
            if (keyId.Length != 40)
            {
                throw new ArgumentNullException("keyId must be 40 characters");
            }
            this.KeyId = keyId;
            _encryptedKey = encryptedKey;
        }

        #endregion

        #region methods

        public async Task UpdateKeyProtectorAsync(IKeyEncyrptionKey currentKeyProtector, IPublicKey newKeyProtector)
        {
            if (currentKeyProtector == null)
            {
                throw new ArgumentNullException("currentKeyProtector");
            }
            if (currentKeyProtector.KeyId != _encryptedKey.KeyId)
            {
                throw new ArgumentException(string.Format("currentKeyProtector.KeyId '{0}' does not match encryptedKey.KeyId '{1}'.", currentKeyProtector.KeyId, _encryptedKey.KeyId));
            }
            if (newKeyProtector == null)
            {
                throw new ArgumentNullException("newKeyProtector");
            }

            // decrypt the key and populate to the x509
            var asymEnc = new AsymmetricEncryptor();
            var decrypted = await asymEnc.DecryptObjectAsync(_encryptedKey, currentKeyProtector);
            var pfxBytes = decrypted as byte[];
            if (pfxBytes == null || !pfxBytes.Any())
            {
                throw new CryptographicException(string.Format("encryptedKey successfull decrypted but was not a valid PFX byte array. Type was '{0}'.", decrypted.GetType().FullName));
            }
            // re-encrypt the key
            var newAsymEncObj = await asymEnc.EncryptObjectAsync(pfxBytes, newKeyProtector.KeyId, newKeyProtector);
            _encryptedKey = newAsymEncObj;
        }

        public async Task<IKeyEncyrptionKey> ToKeyEncyrptionKeyAsync(IKeyEncyrptionKey keyProtector)
        {
            if (keyProtector == null)
            {
                throw new ArgumentNullException("keyProtector");
            }
            if (keyProtector.KeyId != _encryptedKey.KeyId)
            {
                throw new ArgumentException(string.Format("keyProtector.KeyId '{0}' does not match encryptedKey.KeyId '{1}'.", keyProtector.KeyId, _encryptedKey.KeyId));
            }

            // decrypt the key and populate to the x509
            var asymEnc = new AsymmetricEncryptor();
            var decrypted = await asymEnc.DecryptObjectAsync(_encryptedKey, keyProtector);

            var pfxBytes = (byte[])decrypted;
            if (decrypted == null || !pfxBytes.Any())
            {
                throw new CryptographicException(string.Format("encryptedKey successfull decrypted but was not a valid PFX byte array. Type was '{0}'.", decrypted.GetType().FullName));
            }
            IKeyEncyrptionKey protectedKeyAsKeyEncryptionKey;
            try
            {
                var x509 = new X509Certificate2(pfxBytes);
                if (x509.Thumbprint.ToLower() != this.KeyId.ToLower())
                {
                    throw new System.Security.SecurityException(string.Format("The original KeyId '{0}' does not match the certificate thumbprint '{1}'.", this.KeyId, x509.Thumbprint));
                }
                if (x509.HasPrivateKey && x509.PrivateKey == null)
                {
                    var csp = x509.PrivateKey as RSACryptoServiceProvider;
                    if (csp == null)
                    {
                        throw new NotImplementedException(string.Format("encryptedKey does not have a valid RSACryptoServiceProvider private key. Type was '{0}'.", x509.PrivateKey.GetType().FullName));
                    }
                    if (csp.CspKeyContainerInfo.Exportable)
                    {
                        throw new System.Security.SecurityException("The decrypted X509Certificate2 was marked as exportable in the CspKeyContainerInfo. This is not permitted on a protected key.");
                    }
                }
                protectedKeyAsKeyEncryptionKey = Utilities.X509CertificateHelper.GetKeyEncryptionKey(x509);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(string.Format("X509Certificate2 could not be validated. Thumbprint '{0}'. See inner exception for details.", ex));
            }

            return protectedKeyAsKeyEncryptionKey;
        }

        public async Task<byte[]> ToByteArrayAsync()
        {
            this.EnsureNotDisposed();
            return await Task.FromResult(_encryptedKey.ToByteArray());
        }

        public void Dispose()
        {
            _isDisposed = true;
        }


        #endregion

        #region helpers



        #endregion

        private void EnsureNotDisposed()
        {
            if (_isDisposed)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
        }
    }
}
