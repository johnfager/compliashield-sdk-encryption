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

            toHash = "The quick brown fox jumped over the fence.";
            expectedHash = "cae59540cb24e2da1defb0e9b306f25c2e8fa114c265c03854cb75e5ed146b8e";
            hashed = BasicHasher.GetSha256Hash(toHash);
            Assert.AreEqual(expectedHash, hashed);
        }
    }
}
