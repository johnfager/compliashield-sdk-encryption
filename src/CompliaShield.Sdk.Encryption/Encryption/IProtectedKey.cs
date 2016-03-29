
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Threading.Tasks;

    public interface IProtectedKey : IDisposable
    {

        //IKeyEncyrptionKey KeyProtectionKey { get; }

        //AsymmetricallyEncryptedObject 

        Task<IKeyEncyrptionKey> ToKeyEncyrptionKeyAsync(IKeyEncyrptionKey keyProtector);

    }
}
