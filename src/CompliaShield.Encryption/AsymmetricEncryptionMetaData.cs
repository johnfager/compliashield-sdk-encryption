
namespace CompliaShield.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using CompliaShield.Encryption.Utilities;

    [Serializable]
    public class AsymmetricEncryptionMetaData
    {

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string KeyId { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Key2Id { get; set; }

        //[JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        //public string SecretId { get; set; }

        /// <summary>
        /// Asymetrically encrypted password.
        /// </summary>
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public byte[] Reference { get; set; }
        public AsymmetricStrategyOption AsymmetricStrategy { get; set; }

        public virtual void LoadFromByteArray(byte[] input)
        {
            try
            {
                var json = (string)Serializer.DeserializeFromByteArray(input);
                var rec = (AsymmetricEncryptionMetaData)Serializer.DeserializeFromJson(json, typeof(AsymmetricallyEncryptedObject));
                this.KeyId = rec.KeyId;
                this.Key2Id = rec.Key2Id;
                this.Reference = rec.Reference;
                //this.Data = rec.Data;
                this.AsymmetricStrategy = rec.AsymmetricStrategy;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("input was not a validly serialized AsymmetricallyEncryptedObject", ex);
            }
        }

        public virtual byte[] ToByteArray()
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
