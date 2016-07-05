
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security;
    using System.Security.Cryptography;
    using System.Text;

    public class RandomGenerator
    {

        private static readonly object _lock;
        private static readonly Random _random = new Random();

        private Random Random
        {
            get
            {
                return _random;
            }
        }

        #region .ctors

        static RandomGenerator()
        {
            _lock = new object();
            _random = new Random((int)DateTime.UtcNow.Ticks);
        }

        public RandomGenerator()
        {
        }

        #endregion

        public string GenerateSecretCodeUrlSafe(int minLength, int maxLength)
        {
            var random = new RandomGenerator();
            var length = random.RandomNumber(minLength, maxLength);
            var cryptoRandomDataGenerator = new RNGCryptoServiceProvider();
            byte[] buffer = new byte[length];
            cryptoRandomDataGenerator.GetBytes(buffer);
            string uniq = Convert.ToBase64String(buffer).Replace('+', '-').Replace('/', '-').TrimEnd('=').Trim('-');
            return uniq;
        }


        public string RandomString(int size)
        {

            StringBuilder builder = new StringBuilder();
            char ch = '\0';
            int i = 0;

            lock (_lock)
            {
                for (i = 0; i <= size - 1; i++)
                {
                    ch = Convert.ToChar(Convert.ToInt32((26 * this.Random.NextDouble() + 65)));
                    builder.Append(ch);
                }
                this.Random.NextDouble();
            }
            return builder.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max">True maximum number value (not the standard value - 1)</param>
        /// <returns></returns>
        public int RandomNumber(int min, int max)
        {
            lock (_lock)
            {
                return this.Random.Next(min, max + 1); // added because it is a max upper bound
            }
        }

        public string RandomLetters(int size)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            return GenerateRandomFromAllowedValues(chars, size);
        }


        public string RandomLettersUpper(int size)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return GenerateRandomFromAllowedValues(chars, size);
        }

        public string RandomAlphaNumeric(int size)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return GenerateRandomFromAllowedValues(chars, size);
        }


        public string RandomLettersUpperLegibleOnly(int size)
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
            return GenerateRandomFromAllowedValues(chars, size);
        }

        /// <summary>
        /// Omits confusing characters like o, O and 0, or l and 1.
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public string RandomAlphaNumericLegibleOnly(int size)
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghkmnpqrstuvw";
            return GenerateRandomFromAllowedValues(chars, size);
        }

        /// <summary>
        /// Omits confusing characters like o, O and 0, or l and 1.
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        public string RandomPassword()
        {

            return this.RandomPassword(6, 12);
        }

        public string RandomPassword(int maxLength)
        {
            if (maxLength <= 6)
            {
                return this.RandomPassword(maxLength, maxLength);
            }
            // use 6 as the minimum
            return this.RandomPassword(6, maxLength);
        }

        public string RandomPassword(int minLength, int maxLength)
        {
            if (minLength < 4)
            {
                throw new ArgumentException("minLength must be at least 4");
            }
            if (maxLength < minLength)
            {
                throw new ArgumentException("maxLength cannot be less than minLength");
            }
            int size;
            if (minLength == maxLength)
            {
                size = maxLength;
            }
            else
            {
                size = this.RandomNumber(minLength, maxLength);
            }
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghkmnpqrstuvw!@#$%&*-+";
            return GenerateRandomFromAllowedValues(chars, size);
        }

        public SecureString RandomSecureStringPassword(int minLength, int maxLength)
        {
            if (minLength < 4)
            {
                throw new ArgumentException("minLength must be at least 4");
            }
            if (maxLength < minLength)
            {
                throw new ArgumentException("maxLength cannot be less than minLength");
            }
            int size;
            if (minLength == maxLength)
            {
                size = maxLength;
            }
            else
            {
                size = this.RandomNumber(minLength, maxLength);
            }
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghkmnpqrstuvw!@#$%&*-+";
            return GenerateRandomSecureStringFromAllowedValues(chars, size);
        }

        public string RandomNumeric(int size)
        {
            const string chars = "0123456789";
            return GenerateRandomFromAllowedValues(chars, size);
        }

        public char GetLetterOfAlphabet(int position)
        {
            const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZ";
            return Convert.ToChar(chars.Substring(position, 1));
        }

        private string GenerateRandomFromAllowedValues(string allowedValues, int size)
        {
            StringBuilder builder = new StringBuilder();
            int i = 0;
            int alllowLen = allowedValues.Length;

            for (i = 0; i <= size - 1; i++)
            {
                var pos = this.RandomNumber(0, alllowLen - 2);
                builder.Append(allowedValues.Substring(pos, 1));
            }

            var result = builder.ToString();
            return result;
        }


        private SecureString GenerateRandomSecureStringFromAllowedValues(string allowedValues, int size)
        {
            var secureString = new SecureString();
            
            int i = 0;
            int alllowLen = allowedValues.Length;

            for (i = 0; i <= size - 1; i++)
            {
                var pos = this.RandomNumber(0, alllowLen - 2);
                secureString.AppendChar(Convert.ToChar(allowedValues.Substring(pos, 1)));
            }
            return secureString;
        }
    }
}
