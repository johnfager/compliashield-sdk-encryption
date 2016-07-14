
namespace CompliaShield.Sdk.Cryptography.Encryption
{

    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Sdk.Cryptography.Encryption;

    [Serializable]
    public sealed class AsymmetricallyEncryptedBackupObject
    {
        public string AssociationObjectType { get; set; }

        public string AssociationObjectIdentifier { get; set; }

        public Dictionary<string, AsymmetricallyEncryptedObject> BackupObjects { get; set; }

    }
}
