
namespace CompliaShield.Sdk.Cryptography.Encryption.Signing
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Extensions;
    using Utilities;

    public class Verifier
    {
        private RSACryptoServiceProvider _publicKey;
        private EncodingOption _encoding;

        public Verifier(RSACryptoServiceProvider publicKey)
        {
            this.Initialize(publicKey, EncodingOption.Base64String);
        }

        public Verifier(RSACryptoServiceProvider publicKey, EncodingOption encoding)
        {
            this.Initialize(publicKey, encoding);
        }

        private void Initialize(RSACryptoServiceProvider publicKey, EncodingOption encoding)
        {
            if (publicKey == null)
            {
                throw new ArgumentException("publicKey");
            }
            _publicKey = publicKey;
            _encoding = encoding;
        }

        #region MD5

        public bool VerifyMd5Hash(string hashHex, string signedHash)
        {
            byte[] signedBytes;
            if (_encoding == EncodingOption.Base64String)
            {
                signedBytes = Convert.FromBase64String(signedHash);
            }
            else if (_encoding == EncodingOption.HexString)
            {
                signedBytes = Format.HexStringToByteArray(signedHash);
            }
            else
            {
                throw new NotImplementedException(_encoding.ToString());
            }
            return this.VerifyMd5Hash(hashHex, signedBytes);
        }

        public bool VerifyMd5Hash(string hashHex, byte[] signedBytes)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            var isValid = _publicKey.VerifyHash(hashedBytes, CryptoConfig.MapNameToOID("MD5"), signedBytes);
            return isValid;
        }

        #endregion

        #region SHA1

        public bool VerifySha1Hash(string hashHex, string signedHash)
        {
            byte[] signedBytes;
            if (_encoding == EncodingOption.Base64String)
            {
                signedBytes = Convert.FromBase64String(signedHash);
            }
            else if (_encoding == EncodingOption.HexString)
            {
                signedBytes = Format.HexStringToByteArray(signedHash);
            }
            else
            {
                throw new NotImplementedException(_encoding.ToString());
            }
            return this.VerifySha1Hash(hashHex, signedBytes);
        }

        public bool VerifySha1Hash(string hashHex, byte[] signedBytes)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            var isValid = _publicKey.VerifyHash(hashedBytes, CryptoConfig.MapNameToOID("SHA1"), signedBytes);
            return isValid;
        }

        #endregion

    }
}
