
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    // NOTE: This class is sealed due to use of serialization and issues that can arise from missing members.

    [Serializable]
    public abstract class AsymmetricEncryptionMetaDataBase
    {
        
        public abstract string KeyId { get; set; }

        public abstract string Key2Id { get; set; }

        //[JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        //public string SecretId { get; set; }

        /// <summary>
        /// Asymetrically encrypted password.
        /// </summary>
        public abstract byte[] Reference { get; set; }

        public abstract AsymmetricStrategyOption AsymmetricStrategy { get; set; }

        public abstract void LoadFromByteArray(byte[] input);

        public abstract byte[] ToByteArray();

    }
}
