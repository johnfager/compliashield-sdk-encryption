
namespace UnitTestProject1
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using Org.BouncyCastle.Bcpg.OpenPgp;


    public static class PgpUtility
    {
        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to
        /// keyId if it exists.
        /// </summary>
        /// <param name="pgpSec">a secret key ring collection</param>
        /// <param name="keyId">keyId we want</param>
        /// <param name="pass">passphrase to decrypt secret key with</param>
        /// <returns></returns>
        public static PgpPrivateKey FindSecretKey(
            PgpSecretKeyRingBundle pgpSec,
            long keyId,
            char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }


        #region ReadSecretKey methods

        public static PgpSecretKey ReadSecretKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(inputStream);

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey k in kRing.GetSecretKeys())
                {
                    if (k.IsSigningKey)
                    {
                        return k;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }

        public static PgpSecretKey ReadSecretKey(string secretKeyFile)
        {
            PgpSecretKey secretKey;
            using (Stream secretKeyStream = new FileStream(secretKeyFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                secretKey = ReadSecretKey(secretKeyStream);
            }
            return secretKey;
        }

        #endregion

        #region ReadPublicKey methods

        /// <summary>
        /// A simple routine that opens a key ring file and loads the first available key suitable for
        /// encryption.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            //
            // TODO: Determine if we need a better algorithm for key selection
            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            //
            // iterate through the key rings.
            //

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey k in kRing.GetPublicKeys())
                {
                    if (k.IsEncryptionKey)
                    {
                        return k;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        public static PgpPublicKey ReadPublicKey(string publicKeyFile)
        {
            PgpPublicKey publicKey;
            using (Stream publicKeyStream = new FileStream(publicKeyFile, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                publicKey = ReadPublicKey(publicKeyStream);
            }
            return publicKey;
        }


        #endregion


    }
}
