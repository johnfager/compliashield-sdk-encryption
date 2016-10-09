
namespace CompliaShield.Sdk.Cryptography.Hashing
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public static class BasicHasherAlgorithms
    {
        private static readonly string[] _allAlgorithms = new string[] { "MD5", "SHA1", "SHA256" };

        [Obsolete("Use SHA256 instead.")]
        public const string MD5 = "MD5";

        [Obsolete("Use SHA256 instead.")]
        public const string SHA1 = "SHA1";

        public const string SHA256 = "SHA256";

        //public const string RS256 = "RS256";
        //public const string RS384 = "RS384";
        //public const string RS512 = "RS512";
        //public const string RSNULL = "RSNULL";

        public static string[] AllAlgorithms
        {
            get
            {
                return (string[])_allAlgorithms.Clone();
            }
        }

        public static string VerifyAndMapToAlogrithm(string algorithm)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }
            algorithm = algorithm.ToUpper();
            //if (algorithm == "RS256 " || algorithm == "RSNULL")
            //{
            //    algorithm = BasicHasherAlgorithms.SHA256;
            //}
            if (!BasicHasherAlgorithms.AllAlgorithms.Contains(algorithm))
            {
                throw new ArgumentException(string.Format("Algorithm '{0}' is not supported.", algorithm));
            }
            return algorithm;
        }
    }
}
