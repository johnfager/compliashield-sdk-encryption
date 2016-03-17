
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

    public class Signer
    {

        private RSACryptoServiceProvider _privateKey;
        private EncodingOption _encoding;

        /// <summary>
        /// Initializes the signer to output a base64 encoded string
        /// </summary>
        /// <param name="privateKey"></param>
        public Signer(RSACryptoServiceProvider privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentException("privateKey");
            }
            _privateKey = privateKey;
            _encoding = EncodingOption.Base64String;
        }

        public Signer(RSACryptoServiceProvider privateKey, EncodingOption output)
        {
            if (privateKey == null)
            {
                throw new ArgumentException("privateKey");
            }
            _privateKey = privateKey;
            _encoding = output;
        }

        //public void Dispose()
        //{
        //}

        #region MD5

        public string SignMd5Hash(string hex)
        {
            var hashedBytes = Format.HexStringToByteArray(hex);
            return this.SignMd5Hash(hashedBytes);
        }

        public string SignMd5Hash(byte[] hashedBytes)
        {
            var signedHash = _privateKey.SignHash(hashedBytes, CryptoConfig.MapNameToOID("MD5"));
            if (_encoding == EncodingOption.Base64String)
            {
                return Convert.ToBase64String(signedHash);
            }
            else if (_encoding == EncodingOption.HexString)
            {
                return signedHash.ToHexString();
            }
            else
            {
                throw new NotImplementedException(_encoding.ToString());
            }
        }

        #endregion

        #region SHA1

        public string SignSha1Hash(string hex)
        {
            var hashedBytes = Format.HexStringToByteArray(hex);
            return this.SignSha1Hash(hashedBytes);
        }

        public string SignSha1Hash(byte[] hashedBytes)
        {
            var signedHash = _privateKey.SignHash(hashedBytes, CryptoConfig.MapNameToOID("SHA1"));
            if (_encoding == EncodingOption.Base64String)
            {
                return Convert.ToBase64String(signedHash);
            }
            else if (_encoding == EncodingOption.HexString)
            {
                return signedHash.ToHexString();
            }
            else
            {
                throw new NotImplementedException(_encoding.ToString());
            }
        }


        #endregion

    }
}