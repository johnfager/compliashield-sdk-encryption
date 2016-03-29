
namespace CompliaShield.Sdk.X509Certificates
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Newtonsoft.Json;

    public class CertificatePolicy : ICertificatePolicy
    {

        public string CertificatePolicyKey { get; set; }

        [Required]
        public string CommonName { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string RotateTimeDatepart { get; set; }

        public int RotateTimeValue { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string PublishForTimeDatepart { get; set; }

        public int PublishForTimeValue { get; set; }

        [Range(1, 73000)] // 200 years
        public int ValidForDays { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string CertificateAuthorityThumbprint { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public IDictionary<string, string> X509NameDictionary { get; set; }

        public bool ClientAuthentication { get; set; }

        public bool ServerAuthentication { get; set; }

        public bool CodeSigning { get; set; }

        public bool AllPurposes { get; set; }

        #region .ctors

        //public CertificatePolicy(Dictionary<string, string> x509NameDictionary)
        //{
        //    // don't bother initializing if no data
        //    if (x509NameDictionary != null && !x509NameDictionary.Any())
        //    {
        //        this.X509NameDictionary = null;
        //    }
        //    else
        //    {
        //        this.X509NameDictionary = x509NameDictionary;
        //    }
        //}
        
        public void Load(ICertificatePolicy input)
        {
            this.CommonName = input.CommonName;
            this.ValidForDays = input.ValidForDays;
            this.CertificateAuthorityThumbprint = input.CertificateAuthorityThumbprint;
            this.X509NameDictionary = input.X509NameDictionary;
            this.ClientAuthentication = input.ClientAuthentication;
            this.ServerAuthentication = input.ServerAuthentication;
            this.CodeSigning = input.CodeSigning;
            this.AllPurposes = input.AllPurposes;
        }

        #endregion

        #region serialization helpers

        public bool ShouldSerializeX509NameDictionary()
        {
            if(this.X509NameDictionary == null || !this.X509NameDictionary.Any())
            {
                return false;
            }
            return true;
        }

        #endregion

    }
}
