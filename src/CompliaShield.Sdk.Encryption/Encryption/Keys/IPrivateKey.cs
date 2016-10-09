
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    // was IKeyEncryptionKey

    /// <summary>
    /// Abstracts the action of handling unwrapping an encrypted key or signing, allowing for offsite or API access to external key stores including HSM protected key encryption keys.
    /// </summary>
    public interface IPrivateKey : IPublicKey
    {
        //string KeyId { get; }

        Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey);

        Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey, CancellationToken token);

        Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm);

        Task<Tuple<byte[], string>> SignAsync(string hex);

        Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm, CancellationToken token);

    }
}
