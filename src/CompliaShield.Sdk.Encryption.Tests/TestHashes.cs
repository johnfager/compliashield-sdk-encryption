using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using CompliaShield.Sdk.Cryptography.Hashing;

namespace CompliaShield.Sdk.Cryptography.Tests
{
    [TestClass]
    public class TestHashes
    {
        [TestMethod]
        public void TestMethod1()
        {
            var toHash = "pandacat";
            var expectedHash = "9b61a63183cffe1e988f7ccbe77b62c172384efbdf5d10c05f6d431cdf8641cd";
            var hashed = BasicHasher.GetSha256Hash(toHash);
            Assert.AreEqual(expectedHash, hashed);

            //f1965c91412f0ac9cfd52c6ec54b91ba

            expectedHash = "f1965c91412f0ac9cfd52c6ec54b91ba";
            hashed = BasicHasher.GetHash(toHash, "MD5");
            Assert.AreEqual(expectedHash, hashed);

            hashed = BasicHasher.GetMd5Hash(toHash);
            Assert.AreEqual(expectedHash, hashed);

            toHash = "The quick brown fox jumped over the fence.";
            expectedHash = "cae59540cb24e2da1defb0e9b306f25c2e8fa114c265c03854cb75e5ed146b8e";
            hashed = BasicHasher.GetSha256Hash(toHash);
            Assert.AreEqual(expectedHash, hashed);
        }


        [TestMethod]
        public void TestHasherRfc2898()
        {

            for (int i = 0; i < 10; i++)
            {
                var toHash = "pandacat--" + Guid.NewGuid().ToString();
                var hashed = HasherRfc2898.HashValue(toHash);
                Assert.IsTrue(HasherRfc2898.VerifyHashedValues(hashed, toHash));
            }

            var toHash2 = "WUtNSQMd2lviypzb5JUS2Eo7FmA0lLBGEScohGGwBhL__3B3rvq5Za_9gZMts2TaCLSJ0Jth";
            var hashed2 = "ABNrkf5tB5cHm4E5QffIcVMg0iq5uiDSiTswp0viukDzzJn0fu3xcG/o31rL0ARz5w==";
            Assert.IsTrue(HasherRfc2898.VerifyHashedValues(hashed2, toHash2));

            for (int i = 0; i < 10; i++)
            {
                var toHash = "pandacat--" + Guid.NewGuid().ToString() + Guid.NewGuid();
                var hashed = HasherRfc2898.HashValue(toHash, 100000);
                Assert.IsTrue(HasherRfc2898.VerifyHashedValues(hashed, toHash, 100000));
                Assert.IsFalse(HasherRfc2898.VerifyHashedValues(hashed, toHash + "a", 100000));
            }


            for (int i = 0; i < 100; i++)
            {
                var toHash = "pandacat--" + Guid.NewGuid().ToString() + Guid.NewGuid();
                var hashed = HasherRfc2898.HashValue10000(toHash);
                Assert.IsTrue(HasherRfc2898.VerifyHashedValues10000(hashed, toHash));
                Assert.IsFalse(HasherRfc2898.VerifyHashedValues10000(hashed, toHash + "a"));
            }



        }
    }
}
