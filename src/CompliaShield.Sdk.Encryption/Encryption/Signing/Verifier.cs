
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
    using Hashing;

    public class Verifier
    {
        private RSACryptoServiceProvider _publicKey;
        //private EncodingOption _encoding;

        public Verifier(RSACryptoServiceProvider publicKey)
        {
            this.Initialize(publicKey, EncodingOption.Base64String);
        }

        //public Verifier(RSACryptoServiceProvider publicKey, EncodingOption encoding)
        //{
        //    this.Initialize(publicKey, encoding);
        //}

        private void Initialize(RSACryptoServiceProvider publicKey, EncodingOption encoding)
        {
            if (publicKey == null)
            {
                throw new ArgumentException("publicKey");
            }
            _publicKey = publicKey;
            //_encoding = encoding;
        }

        // ----------

        public bool VerifyHash(string hashHex, string signedHash, string algorithm)
        {
            byte[] signedBytes;
            //if (_encoding == EncodingOption.Base64String)
            //{
            //    signedBytes = Convert.FromBase64String(signedHash);
            //}
            //else if (_encoding == EncodingOption.HexString)
            //{
            //    signedBytes = Format.HexStringToByteArray(signedHash);
            //}
            //else
            //{
            //    throw new NotImplementedException(_encoding.ToString());
            //}
            signedBytes = Format.HexStringToByteArray(signedHash);
            return this.VerifyHash(hashHex, signedBytes, algorithm);
        }

        public bool VerifyHash(string hashHex, byte[] signedBytes, string algorithm)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            return this.VerifyHash(hashedBytes, signedBytes, algorithm);
        }

        public bool VerifyHash(byte[] hashedBytes, byte[] signedBytes, string algorithm)
        {
            algorithm = BasicHasherAlgorithms.VerifyAndMapToAlogrithm(algorithm);
            BasicHasher.ValidateDigestLength(algorithm, hashedBytes);
            var isValid = _publicKey.VerifyHash(hashedBytes, algorithm, signedBytes);

#if DEBUG
            var hashHex = hashedBytes.ToHexString();
            var signedHash = signedBytes.ToHexString();
            Console.WriteLine("VerifyHash\t" + hashHex + "\t" + algorithm + "\tsig\t" + signedHash + "\tresult\t" + isValid.ToString().ToLower());
#endif

            return isValid;
        }

        public bool VerifyHash(byte[] hashedBytes, string signedHash, string algorithm)
        {
            algorithm = BasicHasherAlgorithms.VerifyAndMapToAlogrithm(algorithm);
            BasicHasher.ValidateDigestLength(algorithm, hashedBytes);

            byte[] signedBytes;
            //if (_encoding == EncodingOption.Base64String)
            //{
            //    signedBytes = Convert.FromBase64String(signedHash);
            //}
            //else if (_encoding == EncodingOption.HexString)
            //{
            //    signedBytes = Format.HexStringToByteArray(signedHash);
            //}
            //else
            //{
            //    throw new NotImplementedException(_encoding.ToString());
            //}
            signedBytes = Format.HexStringToByteArray(signedHash);
            var isValid = _publicKey.VerifyHash(hashedBytes, algorithm, signedBytes);
#if DEBUG
            var hashHex = hashedBytes.ToHexString();
            Console.WriteLine("VerifyHash\t" + hashHex + "\t" + algorithm + "\tsig\t" + signedHash + "\tresult\t" + isValid.ToString().ToLower());
#endif
            return isValid;
        }




        #region MD5

        public bool VerifyMd5Hash(string hashHex, string signedHash)
        {
            byte[] signedBytes;
            //if (_encoding == EncodingOption.Base64String)
            //{
            //    signedBytes = Convert.FromBase64String(signedHash);
            //}
            //else if (_encoding == EncodingOption.HexString)
            //{
            //    signedBytes = Format.HexStringToByteArray(signedHash);
            //}
            //else
            //{
            //    throw new NotImplementedException(_encoding.ToString());
            //}
            signedBytes = Format.HexStringToByteArray(signedHash);
            return this.VerifyMd5Hash(hashHex, signedBytes);
        }

        public bool VerifyMd5Hash(string hashHex, byte[] signedBytes)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            return this.VerifyMd5Hash(hashedBytes, signedBytes);
        }

        public bool VerifyMd5Hash(byte[] hashedBytes, byte[] signedBytes)
        {
            var isValid = _publicKey.VerifyHash(hashedBytes, CryptoConfig.MapNameToOID("MD5"), signedBytes);
            return isValid;
        }

        #endregion

        #region SHA1

        public bool VerifySha1Hash(string hashHex, string signedHash)
        {
            byte[] signedBytes;
            //if (_encoding == EncodingOption.Base64String)
            //{
            //    signedBytes = Convert.FromBase64String(signedHash);
            //}
            //else if (_encoding == EncodingOption.HexString)
            //{
            //    signedBytes = Format.HexStringToByteArray(signedHash);
            //}
            //else
            //{
            //    throw new NotImplementedException(_encoding.ToString());
            //}
            signedBytes = Format.HexStringToByteArray(signedHash);
            return this.VerifySha1Hash(hashHex, signedBytes);
        }

        public bool VerifySha1Hash(string hashHex, byte[] signedBytes)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            return this.VerifySha1Hash(hashedBytes, signedBytes);
        }


        public bool VerifySha1Hash(byte[] hashedBytes, byte[] signedBytes)
        {
            var isValid = _publicKey.VerifyHash(hashedBytes, CryptoConfig.MapNameToOID("SHA1"), signedBytes);
            return isValid;
        }

        #endregion

        #region SHA56

        public bool VerifySha256Hash(string hashHex, string signedHash)
        {
            byte[] signedBytes;
            //if (_encoding == EncodingOption.Base64String)
            //{
            //    signedBytes = Convert.FromBase64String(signedHash);
            //}
            //else if (_encoding == EncodingOption.HexString)
            //{
            //    signedBytes = Format.HexStringToByteArray(signedHash);
            //}
            //else
            //{
            //    throw new NotImplementedException(_encoding.ToString());
            //}
            signedBytes = Format.HexStringToByteArray(signedHash);
            return this.VerifySha256Hash(hashHex, signedBytes);
        }

        public bool VerifySha256Hash(string hashHex, byte[] signedBytes)
        {
            var hashedBytes = Format.HexStringToByteArray(hashHex);
            return this.VerifySha256Hash(hashedBytes, signedBytes);
        }


        public bool VerifySha256Hash(byte[] hashedBytes, byte[] signedBytes)
        {
            var isValid = _publicKey.VerifyHash(hashedBytes, CryptoConfig.MapNameToOID("SHA256"), signedBytes);
            return isValid;
        }

        #endregion

    }
}
