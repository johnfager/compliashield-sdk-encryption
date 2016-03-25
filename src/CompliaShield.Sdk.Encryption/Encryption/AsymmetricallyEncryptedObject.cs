
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using CompliaShield.Sdk.Cryptography.Utilities;

    [Serializable]
    public sealed class AsymmetricallyEncryptedObject : AsymmetricEncryptionMetaDataBase
    {

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override string KeyId { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override string Key2Id { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string CipherText { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public byte[] Data { get; set; }

        /// <summary>
        /// Asymetrically encrypted password.
        /// </summary>
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override byte[] Reference { get; set; }

        public override AsymmetricStrategyOption AsymmetricStrategy { get; set; }

        public override void LoadFromByteArray(byte[] input)
        {
            try
            {
                var json = (string)Serializer.DeserializeFromByteArray(input);
                var rec = (AsymmetricallyEncryptedObject)Serializer.DeserializeFromJson(json, typeof(AsymmetricallyEncryptedObject));
                this.KeyId = rec.KeyId;
                this.Key2Id = rec.Key2Id;
                this.Reference = rec.Reference;
                this.CipherText = rec.CipherText;
                this.Data = rec.Data;
                this.AsymmetricStrategy = rec.AsymmetricStrategy;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("input was not a validly serialized AsymmetricallyEncryptedObject", ex);
            }
        }

        public override byte[] ToByteArray()
        {
            if (string.IsNullOrEmpty(this.KeyId))
            {
                throw new InvalidOperationException("Cannot serialize to a byte array without a KeyId assigned.");
            }
            var json = Serializer.SerializeToJson(this); // removes the class specific typing
            return Serializer.SerializeToByteArray(json);
        }
    }
}
