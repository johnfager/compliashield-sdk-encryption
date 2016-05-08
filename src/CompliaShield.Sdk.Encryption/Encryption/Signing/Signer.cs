
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
            byte[] signedHash = null;
            try
            {
                signedHash = _privateKey.SignHash(hashedBytes, CryptoConfig.MapNameToOID("MD5"));
            }
            catch(CryptographicException ex)
            {
                if(ex.Message == "Bad Hash.")
                {
                    var cryptoEx = new CryptographicException("Bad Hash; Use BasicHasher.GetMd5HashBytes() to generate a proper hash before calling this method.");
                }
                else
                {
                    throw;
                }
            }

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

        public Tuple<byte[], string> SignMd5(byte[] hashedBytes)
        {
            var cryptoconfig = CryptoConfig.MapNameToOID("MD5");
            var signedHash = _privateKey.SignHash(hashedBytes, cryptoconfig);
            if (_encoding == EncodingOption.Base64String)
            {
                return new Tuple<byte[], string>(signedHash, Convert.ToBase64String(signedHash));
            }
            else if (_encoding == EncodingOption.HexString)
            {
                return new Tuple<byte[], string>(signedHash, signedHash.ToHexString());
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

        public Tuple<byte[], string> SignSha1(byte[] hashedBytes)
        {
            var signedHash = _privateKey.SignHash(hashedBytes, CryptoConfig.MapNameToOID("SHA1"));
            if (_encoding == EncodingOption.Base64String)
            {
                return new Tuple<byte[], string>(signedHash, Convert.ToBase64String(signedHash));
            }
            else if (_encoding == EncodingOption.HexString)
            {
                return new Tuple<byte[], string>(signedHash, signedHash.ToHexString());
            }
            else
            {
                throw new NotImplementedException(_encoding.ToString());
            }
        }


        #endregion

    }
}
