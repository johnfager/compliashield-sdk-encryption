
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Security.Cryptography.X509Certificates;

    public interface IPublicKey
    {
        string KeyId { get; }

        PublicKey PublicKey { get; }
    }
}
