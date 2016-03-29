
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    internal class StringWriterWithEncoding : StringWriter
    {
        public StringWriterWithEncoding(StringBuilder sb, Encoding encoding)
            : base(sb)
        {
            this._encoding = encoding;
        }

        private readonly Encoding _encoding;
        public override Encoding Encoding
        {
            get
            {
                return this._encoding;
            }
        }
    }
}
