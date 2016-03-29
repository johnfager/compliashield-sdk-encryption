
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Abstracts the action of handling unwrapping an encrypted key or signing, allowing for offsite or API access to external key stores including HSM protected key encryption keys.
    /// </summary>
    public interface IKeyEncyrptionKey : IDisposable
    {
        Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey);

        Task<byte[]> UnwrapKeyAsync(byte[] encryptedKey, CancellationToken token);

        Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm);

        Task<Tuple<byte[], string>> SignAsync(byte[] digest, string algorithm, CancellationToken token);

    }
}
