
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
    using Encryption.Keys;
    using Hashing;

    [TestClass]
    public class TestSigning : _baseTest
    {
        [TestMethod]
        public void TestMethod1()
        {
            var cert2 = LoadCertificate();
            var key = new X509Certificate2KeyEncryptionKey(cert2);
            var guid = new Guid();
            var bytesToMd5Hash = Serializer.SerializeToByteArray(guid);
            //var md5Hash = BasicHasher.GetMd5HashBytes(bytesToMd5Hash); //ChecksumHash.GetMD5Hash(bytesToMd5Hash);


            var res = key.SignAsync(bytesToMd5Hash, "MD5").GetAwaiter().GetResult();
            Assert.IsNotNull(res.Item1);
            Assert.IsNotNull(res.Item2);

            var isValid = key.VerifyAsync(bytesToMd5Hash, res.Item1, "MD5").GetAwaiter().GetResult();
            Assert.IsTrue(isValid);

            var isValid2 = key.VerifyAsync(bytesToMd5Hash, res.Item2, "MD5").GetAwaiter().GetResult();
            Assert.IsTrue(isValid2);

            // sha1

            res = key.SignAsync(bytesToMd5Hash, "SHA1").GetAwaiter().GetResult();
            Assert.IsNotNull(res.Item1);
            Assert.IsNotNull(res.Item2);

            isValid = key.VerifyAsync(bytesToMd5Hash, res.Item1, "SHA1").GetAwaiter().GetResult();
            Assert.IsTrue(isValid);

            isValid2 = key.VerifyAsync(bytesToMd5Hash, res.Item2, "SHA1").GetAwaiter().GetResult();
            Assert.IsTrue(isValid2);

        }
    }
}
