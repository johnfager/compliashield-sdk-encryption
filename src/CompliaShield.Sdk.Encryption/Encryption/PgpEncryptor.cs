
namespace CompliaShield.Sdk.Cryptography.Encryption
{
    using System;
    using System.Configuration;
    using System.IO;
    using System.Security.Cryptography;
    // using Bouncy Castle library: http://www.bouncycastle.org/csharp/
    using Org.BouncyCastle.Bcpg;
    using Org.BouncyCastle.Bcpg.OpenPgp;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using CompliaShield.Sdk.Cryptography.Utilities;

    public class PgpEncryptor
    {

        #region methods

        public static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Encrypts a file on disk.
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="publicKeyStream">The public key to use for encryption.</param>
        /// <param name="withIntegrityCheck"></param>
        /// <param name="armor">ASCII armor (should be false unless text is needed for email or compatability).</param>
        /// <param name="compress">Use Zip compression</param>
        public static void EncryptAes256(string inputFile, string outputFile, Stream publicKeyStream, bool withIntegrityCheck, bool armor, bool compress, bool overwrite)
        {
            if (string.IsNullOrEmpty(inputFile))
            {
                throw new ArgumentException("inputFile");
            }
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException(string.Format("The file '{0}' could not be found.", inputFile));
            }
            if (string.IsNullOrEmpty(outputFile))
            {
                throw new ArgumentException("outputFile");
            }
            if (File.Exists(outputFile) && !overwrite)
            {
                throw new InvalidOperationException(string.Format("The file '{0}' already exists and 'overwrite' is false.", inputFile));
            }
            if (publicKeyStream == null)
            {
                throw new ArgumentNullException("publicKeyStream");
            }

            PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);
            using (MemoryStream outputBytes = new MemoryStream())
            {
                //PgpCompressedDataGenerator dataCompressor = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

                //PgpUtilities.WriteFileToLiteralData(dataCompressor.Open(outputBytes), PgpLiteralData.Binary, new FileInfo(inputFile));

                //dataCompressor.Close();

                var compressionAlg = CompressionAlgorithmTag.Uncompressed;
                if (compress)
                {
                    compressionAlg = CompressionAlgorithmTag.Zip;
                }
                byte[] processedData;
                var fiOut = new FileInfo(outputFile);
                var fiIn = new FileInfo(inputFile);
                var inputData = File.ReadAllBytes(inputFile);
                processedData = Compress(inputData, fiIn.Name, compressionAlg);

                PgpEncryptedDataGenerator dataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, withIntegrityCheck, new SecureRandom());
                dataGenerator.AddMethod(pubKey);

                using (Stream outputStream = File.Create(outputFile))
                {
                    if (armor)
                    {
                        using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                        {
                            StreamHelper.WriteStream(dataGenerator.Open(armoredStream, processedData.Length), ref processedData);
                        }
                    }
                    else
                    {
                        StreamHelper.WriteStream(dataGenerator.Open(outputStream, processedData.Length), ref processedData);
                    }
                }
            }
        }

        /// <summary>
        /// Encrypts data using a PGP public key and returns a byte array.
        /// </summary>
        /// <param name="inputData">data to encrypt</param>
        /// <param name="outputName">Reference file name used for compression file name (not a fully qualified path)</param>
        /// <param name="publicKeyStream">The public key to use for encryption.</param>
        /// <param name="withIntegrityCheck"></param>
        /// <param name="armor">ASCII armor (should be false unless text is needed for email or compatability).</param>
        /// <param name="compress">Use Zip compression</param>
        /// <returns>The encrypted byte array</returns>
        public static byte[] EncryptAes256(byte[] inputData, string outputName, Stream publicKeyStream, bool withIntegrityCheck, bool armor, bool compress)
        {

            var pubKey = ReadPublicKey(publicKeyStream);

            var compressionAlg = CompressionAlgorithmTag.Uncompressed;
            if (compress)
            {
                compressionAlg = CompressionAlgorithmTag.Zip;
            }

            byte[] processedData = Compress(inputData, outputName, compressionAlg);

            MemoryStream bOut = new MemoryStream();
            Stream output = bOut;

            if (armor)
            {
                output = new ArmoredOutputStream(output);
            }

            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, withIntegrityCheck, new SecureRandom());

            encGen.AddMethod(pubKey);

            Stream encOut = encGen.Open(output, processedData.Length);

            encOut.Write(processedData, 0, processedData.Length);
            encOut.Close();

            if (armor)
            {
                output.Close();
            }

            return bOut.ToArray();
        }

        public static string DecryptPgpDataToString(string inputData, string privateKeyOnlyFilePath, string privateKeyPassword)
        {
            string output;
            using (Stream inputStream = StreamHelper.GetStream(inputData))
            {
                using (Stream keyIn = File.OpenRead(privateKeyOnlyFilePath))
                {
                    output = DecryptPgpDataToString(inputStream, keyIn, privateKeyPassword);
                }
            }
            return output;
        }

        public static string DecryptPgpDataToString(Stream inputStream, Stream privateKeyStream, string passPhrase)
        {
            string output;

            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Secret key for message not found.");
            }

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                {
                    message = pgpCompressedFactory.NextPgpObject();
                }

                literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetInputStream())
                {
                    output = StreamHelper.GetString(unc);
                }

            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                using (Stream unc = literalData.GetInputStream())
                {
                    output = StreamHelper.GetString(unc);
                }
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

            return output;
        }

        public static void DecryptPgpData(string inputFile, string outputFile, Stream privateKeyStream, string privateKeyPassPhrase, bool overwrite)
        {

            if (string.IsNullOrEmpty(inputFile))
            {
                throw new ArgumentException("inputFile");
            }
            if (!File.Exists(inputFile))
            {
                throw new FileNotFoundException(string.Format("The file '{0}' could not be found.", inputFile));
            }
            if (string.IsNullOrEmpty(outputFile))
            {
                throw new ArgumentException("outputFile");
            }
            if (File.Exists(outputFile) && !overwrite)
            {
                throw new InvalidOperationException(string.Format("The file '{0}' already exists and 'overwrite' is false.", inputFile));
            }
            if (privateKeyStream == null)
            {
                throw new ArgumentNullException("privateKeyStream");
            }

            using (Stream encryptedDataStream = File.OpenRead(inputFile))
            {
                var output = PgpEncryptor.DecryptPgpData(encryptedDataStream, privateKeyStream, privateKeyPassPhrase);

                using (var fileStream = File.Create(outputFile))
                {
                    output.CopyTo(fileStream);
                }
            }
        }

        public static Stream DecryptPgpData(Stream inputStream, Stream privateKeyStream, string privateKeyPassPhrase)
        {

            if (inputStream == null)
            {
                throw new ArgumentNullException("inputStream");
            }
            if (privateKeyStream == null)
            {
                throw new ArgumentNullException("privateKeyStream");
            }

            PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));

            // find secret key
            PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject pgp = null;
            if (pgpFactory != null)
            {
                pgp = pgpFactory.NextPgpObject();
            }

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList encryptedData = null;
            if (pgp is PgpEncryptedDataList)
            {
                encryptedData = (PgpEncryptedDataList)pgp;
            }
            else
            {
                encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
            }

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pubKeyData = null;
            var encryptedObjects = encryptedData.GetEncryptedDataObjects();
            foreach (PgpPublicKeyEncryptedData pubKeyDataItem in encryptedData.GetEncryptedDataObjects())
            {
                privateKey = FindSecretKey(pgpKeyRing, pubKeyDataItem.KeyId, privateKeyPassPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pubKeyData = pubKeyDataItem;
                    break;
                }
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Secret key for message not found.");
            }

            PgpObjectFactory plainFact = null;
            using (Stream clear = pubKeyData.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData compressedData = (PgpCompressedData)message;
                PgpObjectFactory pgpCompressedFactory = null;

                using (Stream compDataIn = compressedData.GetDataStream())
                {
                    pgpCompressedFactory = new PgpObjectFactory(compDataIn);
                }

                message = pgpCompressedFactory.NextPgpObject();
                PgpLiteralData literalData = null;
                if (message is PgpOnePassSignatureList)
                {
                    message = pgpCompressedFactory.NextPgpObject();
                }

                literalData = (PgpLiteralData)message;

                return literalData.GetInputStream();

                //using (Stream unc = literalData.GetInputStream())
                //{
                //    StreamHelper.WriteStream(unc, ref output);
                //}

            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData literalData = (PgpLiteralData)message;
                return literalData.GetInputStream();

                //using (Stream unc = literalData.GetInputStream())
                //{
                //     StreamHelper.WriteStream(unc, ref output);
                //}
            }
            else if (message is PgpOnePassSignatureList)
            {
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PgpException("Message is not a simple encrypted file - type unknown.");
            }

            //return output;
        }


        //public static string GetPrivateKeyXml(string inputData)
        //{
        //    Stream inputStream = StreamHelper.GetStream(inputData);
        //    PgpObjectFactory pgpFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
        //    PgpObject pgp = null;
        //    if (pgpFactory != null)
        //    {
        //        pgp = pgpFactory.NextPgpObject();
        //    }

        //    PgpEncryptedDataList encryptedData = null;
        //    if (pgp is PgpEncryptedDataList)
        //    {
        //        encryptedData = (PgpEncryptedDataList)pgp;
        //    }
        //    else
        //    {
        //        encryptedData = (PgpEncryptedDataList)pgpFactory.NextPgpObject();
        //    }

        //    Stream privateKeyStream = File.OpenRead(PrivateKeyOnlyPath);

        //    // find secret key
        //    PgpSecretKeyRingBundle pgpKeyRing = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));
        //    PgpPrivateKey privateKey = null;

        //    foreach (PgpPublicKeyEncryptedData pked in encryptedData.GetEncryptedDataObjects())
        //    {
        //        privateKey = FindSecretKey(pgpKeyRing, pked.KeyId, Password.ToCharArray());
        //        if (privateKey != null)
        //        {
        //            //pubKeyData = pked;
        //            break;
        //        }
        //    }

        //    // get xml:
        //    RsaPrivateCrtKeyParameters rpckp = ((RsaPrivateCrtKeyParameters)privateKey.Key);
        //    RSAParameters dotNetParams = DotNetUtilities.ToRSAParameters(rpckp);
        //    RSA rsa = RSA.Create();
        //    rsa.ImportParameters(dotNetParams);
        //    string xmlPrivate = rsa.ToXmlString(true);

        //    return xmlPrivate;
        //}

        #endregion

        #region helpers

        /// <summary>
        /// 
        /// </summary>
        /// <param name="clearData"></param>
        /// <param name="fileName">File name reference for compression to include (not fully qualified).</param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        private static byte[] Compress(byte[] clearData, string fileName, CompressionAlgorithmTag algorithm)
        {
            MemoryStream bOut = new MemoryStream();

            PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(algorithm);
            Stream cos = comData.Open(bOut); // open it with the final destination
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();

            // we want to Generate compressed data. This might be a user option later,
            // in which case we would pass in bOut.
            Stream pOut = lData.Open(
            cos,                    // the compressed output stream
            PgpLiteralData.Binary,
            fileName,               // "filename" to store
            clearData.Length,       // length of clear data
            DateTime.UtcNow         // current time
            );

            pOut.Write(clearData, 0, clearData.Length);
            pOut.Close();

            comData.Close();

            return bOut.ToArray();
        }

        private static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
        {
            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);
            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(pass);
        }

        #endregion

    }
}
