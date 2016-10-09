
namespace CompliaShield.Sdk.Cryptography.Tests
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.Linq;
    using CompliaShield.Sdk.Cryptography.Encryption.Keys;
    using CompliaShield.Sdk.Cryptography.Hashing;
    using CompliaShield.Sdk.Cryptography.Utilities;
    using Extensions;

    [TestClass]
    public class TestSigning : _baseTest
    {

        [TestMethod]
        public void TestLength()
        {
            var hex = "f87104a9953455f7a75133208c65f0e1";

            Assert.IsFalse(hex == null || !(hex.Length == 32 | hex.Length == 40));

        }


        [TestMethod]
        public void TestMethod1()
        {
            var cert2 = LoadCertificate();
            var key = new X509Certificate2KeyEncryptionKey(cert2);
            var guid = new Guid();
            var bytesToHash = Serializer.SerializeToByteArray(guid);

            //var algorithms = new string[] { "MD5", "SHA1", "SHA256" };
            foreach (var algorithm in BasicHasherAlgorithms.AllAlgorithms)
            {
                byte[] thisCopy = new byte[bytesToHash.Count()];
                bytesToHash.CopyTo(thisCopy, 0);
                Assert.IsTrue(bytesToHash.SequenceEqual(thisCopy));

                var hashBytes = BasicHasher.GetHashBytes(bytesToHash, algorithm);

                var hashAsHex1 = hashBytes.ToHexString();
                Console.WriteLine("Hash is: " + hashAsHex1);

                var res = key.SignAsync(hashBytes, algorithm).GetAwaiter().GetResult();
                Assert.IsNotNull(res.Item1);
                Assert.IsNotNull(res.Item2);

                //var item2AsByte = Format.HexStringToByteArray(res.Item2);
                //Assert.IsTrue(item2AsByte.SequenceEqual(res.Item1));

                //// check digest
                //var digest2 = BasicHasher.GetHashBytes(bytesToHash, algorithm);
                //Assert.IsTrue(digest2.SequenceEqual(hashBytes));

                var isValid = key.VerifyAsync(hashBytes, res.Item1, algorithm).GetAwaiter().GetResult();
                Assert.IsTrue(isValid);


                //var isValid2 = key.VerifyAsync(hashBytes, res.Item2, algorithm).GetAwaiter().GetResult();
                //Assert.IsTrue(isValid2);

                //Assert.IsTrue(bytesToHash.SequenceEqual(thisCopy));

                var hashHex = BasicHasher.GetHash(bytesToHash, algorithm);
                Console.WriteLine("Hash is now: " + hashHex);

                var asBytes = Format.HexStringToByteArray(hashHex);

                Assert.IsTrue(asBytes.SequenceEqual(hashBytes));

                
                var isValidHex = key.VerifyAsync(hashHex, res.Item2).GetAwaiter().GetResult();
                Assert.IsTrue(isValidHex);

                var hexSigned = key.SignAsync(hashHex).GetAwaiter().GetResult();
                isValidHex = key.VerifyAsync(hashHex, hexSigned.Item2).GetAwaiter().GetResult();
                Assert.IsTrue(isValidHex);

                Console.WriteLine(algorithm + " passed");

            }


            //var res = key.SignAsync(bytesToHash, "MD5").GetAwaiter().GetResult();
            //Assert.IsNotNull(res.Item1);
            //Assert.IsNotNull(res.Item2);

            //var isValid = key.VerifyAsync(bytesToHash, res.Item1, "MD5").GetAwaiter().GetResult();
            //Assert.IsTrue(isValid);

            //var isValid2 = key.VerifyAsync(bytesToHash, res.Item2, "MD5").GetAwaiter().GetResult();
            //Assert.IsTrue(isValid2);

            //var md5HashHex = BasicHasher.GetMd5Hash(bytesToHash); //ChecksumHash.GetMD5Hash(bytesToMd5Hash);
            //var isValidHex = key.VerifyAsync(md5HashHex, res.Item2).GetAwaiter().GetResult();
            //Assert.IsTrue(isValidHex);

            //var signedHex = key.SignAsync(md5HashHex).GetAwaiter().GetResult();
            //isValidHex = key.VerifyAsync(md5HashHex, signedHex.Item2).GetAwaiter().GetResult();
            //Assert.IsTrue(isValidHex);

            //// sha1

            //res = key.SignAsync(bytesToHash, "SHA1").GetAwaiter().GetResult();
            //Assert.IsNotNull(res.Item1);
            //Assert.IsNotNull(res.Item2);

            //isValid = key.VerifyAsync(bytesToHash, res.Item1, "SHA1").GetAwaiter().GetResult();
            //Assert.IsTrue(isValid);

            //isValid2 = key.VerifyAsync(bytesToHash, res.Item2, "SHA1").GetAwaiter().GetResult();
            //Assert.IsTrue(isValid2);

            //var sha1HashHex = BasicHasher.GetSha1Hash(bytesToHash);
            //isValidHex = key.VerifyAsync(sha1HashHex, res.Item2).GetAwaiter().GetResult();
            //Assert.IsTrue(isValidHex);

            //var sha1HexSigned = key.SignAsync(sha1HashHex).GetAwaiter().GetResult();
            //isValidHex = key.VerifyAsync(sha1HashHex, sha1HexSigned.Item2).GetAwaiter().GetResult();
            //Assert.IsTrue(isValidHex);

        }
    }
}
