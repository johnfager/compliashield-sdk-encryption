
namespace CompliaShield.Sdk.Cryptography.Encryption.SerializationHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;

    [JsonConverter(typeof(DictionaryOfStringConverter))]
    public partial class KeyValuePairOfString
    {
        [JsonRequired]
        public string Key { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Value { get; set; }

    }
}
