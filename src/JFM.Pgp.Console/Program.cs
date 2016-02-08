namespace CompliaShield.Pgp.ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // note: all key info is in app.config

            //// pass in a string encrypted data to decrypt
            //string decrypted = CryptoHelper.DecryptPgpData("-----BEGIN PGP MESSAGE----- some pgp-wrapped encrypted string that the private key and password will open");

            var path = IoHelper.BasePath;

            // pass in 2 file paths to generate the encrypted file
            // (IoHelper.BasePath is just the path where the executable is running)
            CryptoHelper.EncryptPgpFile(IoHelper.BasePath + @"\plain-text.txt", IoHelper.BasePath + @"\pgp-encrypted.asc");

            var encStr = System.IO.File.ReadAllText(IoHelper.BasePath + @"\pgp-encrypted.asc");

            string decrypted = CryptoHelper.DecryptPgpData(encStr);

            System.Diagnostics.Debug.WriteLine(decrypted);


            //// if you need to convert a private key from a pgp to xml format:
            //string xmlPPrivateKey = CryptoHelper.GetPrivateKeyXml("-----BEGIN PGP PRIVATE KEY BLOCK----- a pgp private key");
        }
    }
}