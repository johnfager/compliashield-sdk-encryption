
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using CompliaShield.Sdk.Cryptography.Utilities;
    using SerializationHelpers;

    [Serializable]
    public sealed class AsymmetricEncryptionMetaData : AsymmetricEncryptionMetaDataBase
    {
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override Dictionary<string, string> PublicMetadata { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override string KeyId { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override string Key2Id { get; set; }

        //[JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        //public string SecretId { get; set; }

        /// <summary>
        /// Asymetrically encrypted password.
        /// </summary>
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override byte[] Reference { get; set; }

        public override AsymmetricStrategyOption AsymmetricStrategy { get; set; }

        public override void LoadFromByteArray(byte[] input)
        {
            AsymmetricEncryptionMetaDataBase rec = null;
            try
            {
                var json = (string)Serializer.DeserializeFromByteArray(input);
                rec = (AsymmetricEncryptionMetaDataBase)Serializer.DeserializeFromJson(json, typeof(AsymmetricallyEncryptedObject));
                this.SetValues(rec);
            }
            catch (Exception ex)
            {
                bool success = false;
                if (ex.Message.Contains("cast"))
                {
                    // this may have been a direct serialization
                    try
                    {
                        var deserObj = Serializer.DeserializeFromByteArray(input);
                        if(deserObj is AsymmetricEncryptionMetaDataBase)
                        {
                            rec = (AsymmetricEncryptionMetaDataBase)deserObj;
                        }
                        if (rec != null)
                        {
                            this.SetValues((AsymmetricEncryptionMetaDataBase)rec);
                            success = true;
                        }
                    }
                    catch (Exception)
                    {
                        // continue with normal error
                    }
                }

                if (!success)
                {
                    throw new System.Runtime.Serialization.SerializationException("input was not a validly serialized AsymmetricallyEncryptedObject", ex);
                }
            }
        }

        public override byte[] ToByteArray()
        {
            if (string.IsNullOrEmpty(this.KeyId))
            {
                throw new InvalidOperationException("Cannot serialize to a byte array without a KeyId assigned.");
            }
            if (this.PublicMetadata == null)
            {
                this.PublicMetadata = new Dictionary<string, string>();
            }
            this.PublicMetadata["x-serialization-method"] = "json-to-binary-v1";
            this.PublicMetadata["x-serialization-object"] = "AsymmetricEncryptionMetaData";
            var json = Serializer.SerializeToJson(this); // removes the class specific typing
            return Serializer.SerializeToByteArray(json);
        }

        private void SetValues(AsymmetricEncryptionMetaDataBase rec)
        {
            this.KeyId = rec.KeyId;
            this.Key2Id = rec.Key2Id;
            this.Reference = rec.Reference;
            this.AsymmetricStrategy = rec.AsymmetricStrategy;
            this.PublicMetadata = rec.PublicMetadata;
        }

    }
}
