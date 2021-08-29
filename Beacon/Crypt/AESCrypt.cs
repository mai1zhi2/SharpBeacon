using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using Beacon.Crypt.Shared;
using Beacon.Crypt.Internal;
using Beacon.Utils;

namespace Beacon.Crypt
{
    class AESCrypt
    {

        public static byte[] AesEncrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.KeySize = 128;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream encryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(encryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return encryptedData.ToArray();
                    }
                }
            }
        }

        public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv, byte[] hmacKey)
        {

            byte[] encryptedData = AesEncrypt(data, key, iv);

            using (HMACSHA256 hmacsha256 = new HMACSHA256(hmacKey))
            {
                //byte[] ivEncData = iv.Concat(encryptedData).ToArray();
                //byte[] hmac = hmacsha256.ComputeHash(ivEncData);
                //blob = ivEncData.Concat(hmac);

                byte[] hmac = hmacsha256.ComputeHash(encryptedData);
                byte[] hmacHead = new byte[16];
                Array.Copy(hmac, 0, hmacHead, 0, 16);

                byte[] pData = Bytes.Combine(encryptedData, hmacHead);
                return pData;
            }

        }

        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            byte[] decryptedData = default(byte[]);

            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[(data.Length - 32) - 16];
            byte[] hmac = new byte[32];

            Array.Copy(data, iv, 16);
            Array.Copy(data, data.Length - 32, hmac, 0, 32);
            Array.Copy(data, 16, ciphertext, 0, (data.Length - 32) - 16);

            using (HMACSHA256 hmacsha256 = new HMACSHA256(key))
            {
                byte[] computedHash = hmacsha256.ComputeHash(iv.Concat(ciphertext).ToArray());
                for (int i = 0; i < hmac.Length; i++)
                {
                    if (computedHash[i] != hmac[i])
                    {
#if DEBUG
                        Console.WriteLine("Invalid HMAC: {0}", i);
#endif
                        return decryptedData;
                    }
                }
                decryptedData = AesDecrypt(ciphertext, key, iv);
            }
            return decryptedData;
        }

        public static byte[] AesDecrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;
                aesAlg.KeySize = 128;
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream decryptedData = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(decryptedData, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return decryptedData.ToArray();
                    }
                }
            }
        }
    }
}
