

namespace CompliaShield.Sdk.X509Certificates
{

    using System;
    using System.Collections.Generic;

    public interface ICertificatePolicy
    { 
        string CertificatePolicyKey { get; set; }

        string CommonName { get; set; }

        int ValidForDays { get; set; }

        string CertificateAuthorityThumbprint { get; set; }

        IDictionary<string, string> X509NameDictionary { get; set; }

        bool ClientAuthentication { get; set; }

        bool ServerAuthentication { get; set; }

        bool CodeSigning { get; set; }

        bool AllPurposes { get; set; }

        string RotateTimeDatepart { get; set; }

        int RotateTimeValue { get; set; }

        string PublishForTimeDatepart { get; set; }

        int PublishForTimeValue { get; set; }
    }
}
