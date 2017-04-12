
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using SerializationHelpers;
    using CompliaShield.Sdk.Cryptography.Utilities;

    [Serializable]
    public sealed class AsymmetricallyEncryptedObject : AsymmetricEncryptionMetaDataBase
    {
        private Dictionary<string, string> _publicMetadata;

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public override Dictionary<string, string> PublicMetadata
        {
            get
            {
                //if (_publicMetadata == null)
                //{
                //    _publicMetadata = new StringDictionaryCaseInsensitive();
                //}
                return _publicMetadata;
            }
            set
            {
                _publicMetadata = value;
            }
        }

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

        private AsymmetricStrategyOption _asymmetricStrategy;

        public override AsymmetricStrategyOption AsymmetricStrategy
        {
            // NOTE: Typo of Aes256_200000 was removed but is preserved as obsolete
            get
            {
#pragma warning disable 0618
                if (_asymmetricStrategy == AsymmetricStrategyOption.Aes256_200000)
                {
                    _asymmetricStrategy = AsymmetricStrategyOption.Aes256_20000;
                }
#pragma warning restore 0618
                return _asymmetricStrategy;
            }
            set
            {
#pragma warning disable 0618
                if (value == AsymmetricStrategyOption.Aes256_200000)
                {
                    value = AsymmetricStrategyOption.Aes256_20000;
                }
#pragma warning restore 0618
                _asymmetricStrategy = value;

            }
        }


        public override void LoadFromByteArray(byte[] input)
        {
            try
            {
                var json = (string)Serializer.DeserializeFromByteArray(input);
                var rec = (AsymmetricallyEncryptedObject)Serializer.DeserializeFromJson(json, typeof(AsymmetricallyEncryptedObject));
                this.SetValues(rec);
            }
            catch (Exception ex)
            {
                bool success = false;
                if (ex.Message.Contains("cast") && ex.Message.Contains("AsymmetricallyEncryptedObject' to type 'System.String'"))
                {
                    // this may have been a direct serialization
                    try
                    {
                        var asymObj = Serializer.DeserializeFromByteArray(input) as AsymmetricallyEncryptedObject;
                        if (asymObj != null)
                        {
                            this.SetValues(asymObj);
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
            this.PublicMetadata["x-serialization-object"] = "AsymmetricallyEncryptedObject";
            var json = Serializer.SerializeToJson(this); // removes the class specific typing
            //Console.WriteLine(json);
            return Serializer.SerializeToByteArray(json);
        }


        private void SetValues(AsymmetricallyEncryptedObject rec)
        {
            this.KeyId = rec.KeyId;
            this.Key2Id = rec.Key2Id;
            this.Reference = rec.Reference;
            this.CipherText = rec.CipherText;
            this.Data = rec.Data;
            this.AsymmetricStrategy = rec.AsymmetricStrategy;
            this.PublicMetadata = rec.PublicMetadata;
        }
    }
}
