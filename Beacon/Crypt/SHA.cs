using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using Beacon.Crypt.Shared;
using Beacon.Profiles;
using Beacon.Utils;

namespace Beacon.Crypt
{
    class SHA
    {
        public static byte[] Sha256(byte[] srcBuff)
        {

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] bytes_sha256_out = sha256.ComputeHash(srcBuff);
#if DEBUG
                Console.WriteLine(Convert.ToBase64String(bytes_sha256_out));
#endif
                return bytes_sha256_out;
            }

        }

        public static byte[] Sha256(byte[] encryptedData, byte[] hmackey)
        {

            HMACSHA256 hmacsha256 = new HMACSHA256(hmackey);

            //byte[] ivEncData = iv.Concat(encryptedData).ToArray();
            //byte[] hmac = hmacsha256.ComputeHash(ivEncData);
            //blob = ivEncData.Concat(hmac);

            byte[] hmac = hmacsha256.ComputeHash(encryptedData);
            byte[] hmacHead = new byte[16];
            Array.Copy(hmac, 0, hmacHead, 0, 16);

            return hmacHead;

        }
    }
}
