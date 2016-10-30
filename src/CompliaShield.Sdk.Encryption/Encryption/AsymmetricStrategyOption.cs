
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    [JsonConverter(typeof(StringEnumConverter))]
    public enum AsymmetricStrategyOption
    {
        Undefined = 0,
        Legacy_Aes2 = 1,
        Aes256_200000 = 20,
        Aes256_1000 = 100,
        //Aes256_100 = 140,
        Aes256_5 = 150
    }
}
