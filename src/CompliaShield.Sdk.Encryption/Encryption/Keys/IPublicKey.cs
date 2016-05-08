
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    public interface IPublicKey : IDisposable
    {
        string KeyId { get; }

        DateTime NotBefore { get; }

        DateTime NotAfter { get; }

        PublicKey PublicKey { get; }

        Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm);

        Task<bool> VerifyAsync(byte[] digest, byte[] signature, string algorithm, CancellationToken token);
        
        Task<bool> VerifyAsync(byte[] digest, string signature, string algorithm);

        Task<bool> VerifyAsync(byte[] digest, string signature, string algorithm, CancellationToken token);

        string PublicKeyToPEM();

    }
}
