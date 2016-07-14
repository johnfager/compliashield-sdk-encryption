
namespace CompliaShield.Sdk.Cryptography.Encryption
{

    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using SerializationHelpers;

    [Serializable]
    public abstract class AsymmetricEncryptionMetaDataBase
    {
       
        public abstract Dictionary<string, string> PublicMetadata { get; set; }
        
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
