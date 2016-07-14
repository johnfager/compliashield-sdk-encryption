
namespace CompliaShield.Sdk.Cryptography.Encryption.SerializationHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    [Serializable]
    public class StringDictionaryCaseInsensitive : Dictionary<string, string>
    {

        #region properties



        #endregion

        #region .ctors

        public StringDictionaryCaseInsensitive() : base(StringComparer.OrdinalIgnoreCase)
        {
        }

        #endregion

        #region methods



        #endregion

        #region helpers



        #endregion

    }
}
