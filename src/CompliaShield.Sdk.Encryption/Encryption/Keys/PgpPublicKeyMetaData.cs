
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

        private DateTime _expires;

        public DateTime Expires
        {
            get
            {
                // option for being set manually if the others are not
                if (this.CreatedOnUtc.HasValue && this.ValidDays.HasValue)
                {
                    return this.CreatedOnUtc.Value.AddDays(this.ValidDays.Value);
                }
                else
                {
                    return _expires;
                }
            }
            set
            {
                _expires = value;
            }
        }

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

        public static PgpPublicKeyMetaData GetPublicKeysHeirarchical(Stream inputStream)
        {
            var keys = GetPublicKeys(inputStream).ToList();
            var master = keys.FirstOrDefault(x => x.IsMasterKey);
            var subKeys = keys.Where(x => !x.IsMasterKey);
            master.SubKeys = subKeys;
            return master;
        }

        public static IEnumerable<PgpPublicKeyMetaData> GetPublicKeys(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    var keyMeta = new PgpPublicKeyMetaData();
                    keyMeta.Load(key);
                    yield return keyMeta;
                }
            }
        }

    }
}
