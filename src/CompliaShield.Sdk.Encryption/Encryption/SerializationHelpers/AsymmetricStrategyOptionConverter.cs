
namespace CompliaShield.Sdk.Cryptography.Encryption.SerializationHelpers
{
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public class AsymmetricStrategyOptionConverter : JsonConverter
    {
        static StringEnumConverter  converter = new StringEnumConverter();

        public override bool CanConvert(Type objectType)
        {
            Type type = IsNullableType(objectType) ? Nullable.GetUnderlyingType(objectType) : objectType;
            return type.IsEnum;
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            bool isNullable = IsNullableType(objectType);
            Type enumType = isNullable ? Nullable.GetUnderlyingType(objectType) : objectType;

            string[] names = Enum.GetNames(enumType);

            var converter = new StringEnumConverter();


            if (reader.TokenType == JsonToken.String)
            {

                string enumText = reader.Value.ToString();
                if(enumText != null && enumText.ToLower() == "aes256_200000")
                {
                    // fix this error
                    enumText = "Aes256_20000";
                }                
            }
           
            return converter.ReadJson;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteValue(value.ToString());
        }

        private bool IsNullableType(Type t)
        {
            return (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Nullable<>));
        }
    }
}
