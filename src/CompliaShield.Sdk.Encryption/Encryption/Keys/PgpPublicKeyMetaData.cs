
namespace CompliaShield.Sdk.Cryptography.Encryption.Keys
{
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;


    public partial class PgpPublicKeyMetaData
    {

        public virtual string KeyId { get; set; }

        public virtual string KeyIdShort { get; set; }

        public virtual bool IsMasterKey { get; set; }

        public virtual bool IsEncryptionKey { get; set; }

        public virtual string Algorithm { get; set; }

        public virtual int BitStrength { get; set; }

        public virtual int Version { get; set; }

        public virtual string IdentityName { get; set; }

        public virtual string IdentityEmail { get; set; }

        public DateTime? CreatedOnUtc { get; set; }

        public int? ValidDays { get; set; }

        //private DateTime _expires;

        public DateTime Expires { get; set; }
        //{
        //    get
        //    {
        //        // option for being set manually if the others are not
        //        if (this.CreatedOnUtc.HasValue && this.ValidDays.HasValue)
        //        {
        //            return this.CreatedOnUtc.Value.AddDays(this.ValidDays.Value);
        //        }
        //        else
        //        {
        //            return _expires.GetValueOrDefault();
        //        }
        //    }
        //    set
        //    {
        //        _expires = value;
        //    }
        //}

        public virtual IEnumerable<PgpPublicKeyMetaData> SubKeys { get; set; }

        private void Load(PgpPublicKey key)
        {
            this.KeyId = key.KeyId.ToString("X");
            if (this.KeyId != null && this.KeyId.Length >= 15)
            {
                this.KeyIdShort = this.KeyId.Substring(this.KeyId.Length - 8);
            }
            this.Algorithm = key.Algorithm.ToString();
            this.BitStrength = key.BitStrength;
            this.IsMasterKey = key.IsMasterKey;
            this.IsEncryptionKey = key.IsEncryptionKey;
            this.Version = key.Version;
            this.CreatedOnUtc = key.CreationTime.ToUniversalTime();
            this.ValidDays = key.ValidDays;
            this.Expires = this.CreatedOnUtc.Value.AddDays(this.ValidDays.Value); 

            try
            {
                var userIds = key.GetUserIds();
                if (userIds != null)
                {
                    var enumerator = userIds.GetEnumerator();
                    if (enumerator.MoveNext())
                    {
                        var userIdentity = enumerator.Current as string;
                        if (userIdentity != null && userIdentity.Contains("<") && userIdentity.Contains(">"))
                        {
                            var name = userIdentity.Substring(0, userIdentity.IndexOf("<") - 1).Trim();
                            this.IdentityName = name;
                            var email = userIdentity.Substring(userIdentity.IndexOf("<") + 1);
                            email = email.Substring(0, email.IndexOf(">")).Trim();
                            this.IdentityEmail = email;
                        }
                    }
                }
            }
            catch { }

        }


        public virtual bool Validate(out IEnumerable<string> errors)
        {
            this.ValidateInternal(out errors);
            if (errors == null || !errors.Any())
            {
                return true;
            }
            return false;
        }

        private void ValidateInternal(out IEnumerable<string> errors)
        {
            var errList = new List<string>();

            if (this.Expires <= DateTime.UtcNow)
            {
                errList.Add("Certificate was expired.");
            }

            // ensure at least 1 encryption key
            if (!this.IsEncryptionKey)
            {
                if (this.SubKeys == null)
                {
                    errList.Add("No encryption keys are present.");
                }
                // get the encryption key
                var encryptionKey = this.SubKeys.FirstOrDefault(x => x.IsEncryptionKey && x.Expires > DateTime.Now);
                if (encryptionKey == null)
                {
                    errList.Add("No encryption keys are present.");
                }
            }

            ValidateBitStrength(this, errList);

            ValidateVersion(this, errList);

            if (!errList.Any())
            {
                errors = null;
                return;
            }
            errors = errList;
        }

        private static bool ValidateBitStrength(PgpPublicKeyMetaData key, List<string> errors)
        {
            // key strength
            bool validStregth = false;
            if (key.BitStrength == 2048 || key.BitStrength == 4096)
            {
                validStregth = true;
            }
            if (!validStregth)
            {
                errors.Add(string.Format("Key '{0}' requires either 2048 or 4096 bit strength.", key.KeyIdShort));
                return false;
            }
            if (key.SubKeys != null && key.SubKeys.Any())
            {
                foreach (var subKey in key.SubKeys)
                {
                    var isValid = ValidateBitStrength(subKey, errors);
                    if (!isValid)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        private static bool ValidateVersion(PgpPublicKeyMetaData key, List<string> errors)
        {
            // key strength
            if (key.Version < 3)
            {
                errors.Add(string.Format("Key '{0}' must be >= version 3.", key.KeyIdShort));
                return false;
            }
            if (key.SubKeys != null && key.SubKeys.Any())
            {
                foreach (var subKey in key.SubKeys)
                {
                    var isValid = ValidateVersion(subKey, errors);
                    if (!isValid)
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public static PgpPublicKeyMetaData GetPublicKeysHeirarchical(Stream inputStream)
        {
            var keys = GetPublicKeys(inputStream).ToList();
            var master = keys.FirstOrDefault(x => x.IsMasterKey);
            var subKeys = keys.Where(x => !x.IsMasterKey).ToList();
            master.SubKeys = subKeys;
            return master;
        }

        public static IEnumerable<PgpPublicKeyMetaData> GetPublicKeys(Stream inputStream) //, bool disallowPrivateKeys)
        {

            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            //if (disallowPrivateKeys)
            //{
            //    PgpSecretKeyRingBundle pgpKeyRing = null;
            //    try
            //    {
            //        pgpKeyRing = new PgpSecretKeyRingBundle(inputStream);
            //    }
            //    catch
            //    {
            //    }
            //    if (pgpKeyRing != null && pgpKeyRing.Count > 0)
            //    {
            //        throw new System.Security.SecurityException("Private keys are not allowed.");
            //    }
            //}

            var list = new List<PgpPublicKeyMetaData>();

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    var keyMeta = new PgpPublicKeyMetaData();
                    keyMeta.Load(key);
                    list.Add(keyMeta);
                }
            }
            return list;
        }

    }
}
