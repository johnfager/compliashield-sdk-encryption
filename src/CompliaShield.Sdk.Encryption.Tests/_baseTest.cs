
namespace CompliaShield.Sdk.Cryptography.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Management;
    using System.Reflection;
    using System.Security.Cryptography;
    using Utilities;
    using Encryption;
    using System.Security;

    public abstract class _baseTest
    {

        protected const string CERT_FOLDER = @"cert\";

        #region helpers

        public X509Certificate2 GetCertificateByThumbprint(StoreLocation storeLocation, string thumbprint)
        {
            X509Store certStore = new X509Store(StoreName.My, storeLocation);
            try
            {
                try
                {
                    certStore.Open(OpenFlags.ReadOnly);
                }
                catch (Exception ex)
                {
                    var outerEx = new SecurityException(string.Format("Failed to open X509Store in '{0}'.", storeLocation.ToString()), ex);
                    throw outerEx;
                }
                

                foreach(var thisCert in certStore.Certificates)
                {
                    Console.WriteLine(thisCert.Thumbprint + "\t" + thisCert.Subject);
                }

                var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certCollection == null || certCollection.Count == 0)
                {
                    throw new ArgumentException(string.Format("thumbprint '{0}' does not match any certificates in '{1}'.", thumbprint, storeLocation.ToString()));
                }
                var cert = certCollection[0];
                return cert;
            }
            finally
            {
                certStore.Close();
            }
        }

        protected void CheckLineLengthDifferences(FileInfo fiTempEncrypted, StringBuilder stb)
        {

            var dic = new Dictionary<int, string>();

            // base 64
            var lines = File.ReadLines(fiTempEncrypted.FullName + ".txt");

            int i = 1;
            foreach (var line in lines)
            {
                dic[i] = line.Length.ToString();
                i++;
            }

            lines = File.ReadLines(fiTempEncrypted.FullName + ".base64");
            i = 1;
            foreach (var line in lines)
            {
                dic[i] += "\t" + line.Length.ToString();
                i++;
            }

            lines = File.ReadLines(fiTempEncrypted.FullName + ".base36");
            i = 1;
            foreach (var line in lines)
            {
                dic[i] += "\t" + line.Length.ToString();
                i++;
            }

            stb.AppendLine();
            stb.AppendLine("--------------------");
            stb.AppendLine();

            stb.AppendLine("Line\tlenPlain\tlen64\tlen36");

            foreach (var item in dic)
            {
                stb.AppendLine(item.Key.ToString() + "\t" + item.Value);
            }

            File.WriteAllText(fiTempEncrypted.FullName + "_report.txt", stb.ToString());
        }

        protected static X509Certificate2 LoadCertificate()
        {
            string pfxFilePath = (CERT_FOLDER + "DO_NOT_TRUST Testing.pfx");
            if (!File.Exists(pfxFilePath))
            {
                throw new FileNotFoundException("Could not load PFX file at path: " + pfxFilePath);
            }
            string pfxPwFilePath = CERT_FOLDER + "DO_NOT_TRUST Testing_password.txt";
            if (!File.Exists(pfxPwFilePath))
            {
                throw new FileNotFoundException("Could not load PFX password file at path: " + pfxPwFilePath);
            }
            string pfxPw = File.ReadAllText(pfxPwFilePath);
            var cert2 = new X509Certificate2(pfxFilePath, pfxPw, X509KeyStorageFlags.Exportable);
            return cert2;
        }

        protected static X509Certificate2 LoadCertificate2()
        {
            string pfxFilePath = (CERT_FOLDER + "DO_NOT_TRUST Testing2.pfx");
            if (!File.Exists(pfxFilePath))
            {
                throw new FileNotFoundException("Could not load PFX file at path: " + pfxFilePath);
            }
            string pfxPwFilePath = CERT_FOLDER + "DO_NOT_TRUST Testing2_password.txt";
            if (!File.Exists(pfxPwFilePath))
            {
                throw new FileNotFoundException("Could not load PFX password file at path: " + pfxPwFilePath);
            }
            string pfxPw = File.ReadAllText(pfxPwFilePath);
            var cert2 = new X509Certificate2(pfxFilePath, pfxPw, X509KeyStorageFlags.Exportable);
            return cert2;
        }

        #endregion

    }
}
