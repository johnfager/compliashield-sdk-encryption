
namespace CompliaShield.Sdk.Cryptography.Encryption.SerializationHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    public partial class DictionaryOfStringConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var kvp = value as KeyValuePairOfString;
            if (kvp != null)
            {
                writer.WriteStartObject();
                writer.WritePropertyName(kvp.Key);
                serializer.Serialize(writer, kvp.Value);
                writer.WriteEndObject();
            }
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject jObject = JObject.Load(reader);

            foreach (var prop in jObject)
            {
                return new KeyValuePairOfString() { Key = prop.Key, Value = prop.Value.ToString() };
            }

            return null;
        }

        public override bool CanConvert(Type objectType)
        {
            return typeof(KeyValuePairOfString).IsAssignableFrom(objectType);
        }
    }
}
