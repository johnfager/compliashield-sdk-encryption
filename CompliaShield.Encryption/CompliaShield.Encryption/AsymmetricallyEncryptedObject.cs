
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
    public class AsymmetricallyEncryptedObject : AsymmetricEncryptionMetaData
    {

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string CipherText { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public byte[] Data { get; set; }
        
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
    }
}
