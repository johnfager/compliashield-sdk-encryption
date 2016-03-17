
namespace CompliaShield.Sdk.Cryptography.Extensions
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;
    using System.Threading.Tasks;

    public static class SecureStringExtensions
    {
        public static string ConvertToUnsecureString(this SecureString helper)
        {
            if (helper == null)
            {
                throw new ArgumentNullException("helper");
            }
            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(helper);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
        
        public static byte[] ToByteArray(this SecureString helper)
        {
            if (helper == null)
            {
                throw new ArgumentNullException("helper");
            }

            byte[] secureStringBytes = null;
            // Convert System.SecureString to Pointer
            IntPtr unmanagedBytes = Marshal.SecureStringToGlobalAllocAnsi(helper);
            try
            {
                unsafe
                {
                    byte* byteArray = (byte*)unmanagedBytes.ToPointer();
                    // Find the end of the string
                    byte* pEnd = byteArray;
                    while (*pEnd++ != 0) { }
                    // Length is effectively the difference here (note we're 1 past end) 
                    int length = (int)((pEnd - byteArray) - 1);
                    secureStringBytes = new byte[length];
                    for (int i = 0; i < length; ++i)
                    {
                        // Work with data in byte array as necessary, via pointers, here
                        secureStringBytes[i] = *(byteArray + i);
                    }
                }
            }
            finally
            {
                // This will completely remove the data from memory
                Marshal.ZeroFreeGlobalAllocAnsi(unmanagedBytes);
            }
            return secureStringBytes;
        }


    }
}
