using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace GoogleAuthenticator
{
     
    /// <summary>
    /// Google Authenticator implements the algorithms defined in RFC 4226 and RFC 6238. The first is a counter based implementation of two-factor authentication. 
    /// 
    /// The second is a time-based implementation. First, the server and the user agree on a secret key to use as the seed value for the hashing function.
    /// Supporting URLs
    /// http://www.inovex.ca/working-with-oath-two-factor-authentication-and-net/
    /// 
    /// http://online-calculators.appspot.com/base32/
    /// 
    /// A better one is here
    /// http://toolsmother.com/base-32-64-encoder/
    /// 
    /// Configure Google Authenticator
    /// After installing Google Authenticator you will be prompted to add an account. Select “Enter provided key” to manually enter the account name, key, and choose 
    /// the type of algorithm to run. For our test we will simple call the account “demo account” and select “Counter based” to implement a HOTP instance. For the key 
    /// we will use the secret password “secretpassword” however we need to enter the key as a 32-bit encoded string for Google Authenticator to work. There are a 
    /// number of resources out there that will show you how to 32-bit encode your passwords, for now just trust that “secretpassword” is represented as 
    /// “onswg4tforygc43to5xxeza=” when 32-bit encoded. The "=" is a padding character which is not always needed. The Google Authenticator will work with our without padding.
    /// 
    /// Open Google Authenticator and click to get a new token, you should receive the value 323056.
    /// 
    /// 
    /// Calling our HOTP method with the parameters key=”secretpassword” and counter=1 should yield the same token 323056.
    /// 
    /// Time base code is calcualted by counter = (ulong)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / 30;
    /// 
    /// </summary>
    class Program
    {

        public static readonly string secret = "secretpassword";

        //Test with real Google account
        //otpauth://totp/Google%3Ajudek15%40gmail.com?secret=vmrikqsw5h7mtsqyd5n3y6wqqdywydl5&issuer=Google

        public static readonly string Googlesecret = "vmrikqsw5h7mtsqyd5n3y6wqqdywydl5";


        public static readonly DateTime UNIX_EPOCH = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        
        static void Main(string[] args)
        {
            string base32encoded = Base32.ToBase32String(Encoding.UTF8.GetBytes(secret));

            Console.WriteLine("Test string");
            Console.WriteLine("============");
            
            Console.WriteLine("Secret:" + secret);

            Console.WriteLine("Secret base32 encoded no padding:" + base32encoded);

            Console.WriteLine("First Code:" + Program.HOTP(secret, 1));

            Console.WriteLine("Time based rolling code:" + Program.HOTP(secret, (ulong)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / 30));

            Console.WriteLine();

            Console.WriteLine("Real Google account");
            Console.WriteLine("============");

            Console.WriteLine("Secret: binary");

            Console.WriteLine("Secret base32 encoded no padding:" + Googlesecret);

            byte[] GoogleSecretbytes = Base32.FromBase32String(Googlesecret);

            Console.WriteLine("First Code:" + Program.HOTP2(GoogleSecretbytes, 1));

            Console.WriteLine("Time based rolling code:" + Program.HOTP2(GoogleSecretbytes, (ulong)(DateTime.UtcNow - UNIX_EPOCH).TotalSeconds / 30));


        }


        public static string HOTP(string key, ulong counter, int digits = 6)
        {
            return HOTP2(System.Text.Encoding.ASCII.GetBytes(key), counter, digits);
        }


        public static string HOTP2(byte[] key, ulong counter, int digits = 6)
        {
            // compute SHA-1 HMAC of the key
            System.Security.Cryptography.HMACSHA1 hmac =
                new System.Security.Cryptography.HMACSHA1(key, true);

            // convert the counter to bytes, check if the system is little endian and reverse if necessary
            byte[] counter_bytes = BitConverter.IsLittleEndian ? BitConverter.GetBytes(counter).Reverse().ToArray() : BitConverter.GetBytes(counter);

            // compute the hash using the counter value
            byte[] hmac_result = hmac.ComputeHash(counter_bytes);

            // get the last 4 bits of the HMAC Result to determine the offset
            int offset = hmac_result[hmac_result.Length - 1] & 0xf;

            // get the value of 4 bytes of the HMAC Result starting at the offset position
            int bin_code = (hmac_result[offset] & 0x7f) << 24
                | (hmac_result[offset + 1] & 0xff) << 16
                | (hmac_result[offset + 2] & 0xff) << 8
                | (hmac_result[offset + 3] & 0xff);

            // HOTP = bin_code modulo 10^(digits)
            int hotp = bin_code % (int)Math.Pow(10, digits);

            // truncate the string to the number of significant digits
            return hotp.ToString(String.Empty.PadRight(digits, '0'));
        }

    }
}
