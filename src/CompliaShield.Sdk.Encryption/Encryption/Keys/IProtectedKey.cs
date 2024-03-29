
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using System;
    using System.Threading.Tasks;

    public interface IProtectedKey : IDisposable
    {

        //IKeyEncyrptionKey KeyProtectionKey { get; }

        //AsymmetricallyEncryptedObject

        string KeyId { get; }

        Task<byte[]> ToByteArrayAsync();

        Task<IPrivateKey> ToKeyEncyrptionKeyAsync(IPrivateKey keyProtector);

        Task UpdateKeyProtectorAsync(IPrivateKey currentKeyProtector, IPublicKey newKeyProtector);

    }
}
