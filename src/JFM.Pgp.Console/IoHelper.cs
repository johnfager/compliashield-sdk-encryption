using System.IO;
using System.Reflection;

namespace CompliaShield.Pgp.ConsoleApp
{
    public static class IoHelper
    {
        //public static  string BasePath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

        public static string BasePath = @"C:\temp\pgp"; // Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);


        public static Stream GetStream(string stringData)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(stringData);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static string GetString(Stream inputStream)
        {
            string output;
            using (StreamReader reader = new StreamReader(inputStream))
            {
                output = reader.ReadToEnd();
            }
            return output;
        }

        public static void WriteStream(Stream inputStream, ref byte[] dataBytes)
        {
            using (Stream outputStream = inputStream)
            {
                outputStream.Write(dataBytes, 0, dataBytes.Length);
            }
        }
    }
}
