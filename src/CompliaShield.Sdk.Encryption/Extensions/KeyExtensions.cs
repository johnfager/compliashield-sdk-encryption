
namespace CompliaShield.Sdk.Cryptography.Extensions
{
    using Encryption.Keys;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    public static class KeyExtensions
    {

        internal static RSACryptoServiceProvider ToRSACryptoServiceProvider(this IPublicKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException("publicKey");
            }
            if (publicKey.PublicKey == null)
            {
                throw new ArgumentNullException(string.Format("publicKey.PublicKey on KeyId '{0}' is NULL.", publicKey.KeyId));
            }
            if (publicKey.PublicKey.Key == null)
            {
                throw new ArgumentNullException(string.Format("publicKey.PublicKey.Key on KeyId '{0}' is NULL.", publicKey.KeyId));
            }
            var rsa = publicKey.PublicKey.Key as RSACryptoServiceProvider;
            if (rsa == null)
            {
                throw new ArgumentNullException(string.Format("publicKey.PublicKey.Key on KeyId '{0}' is not a valid RSACryptoServiceProvider.", publicKey.KeyId));
            }
            return rsa;
        }


    }
}
