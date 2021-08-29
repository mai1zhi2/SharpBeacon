using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Beacon.Crypt.Internal;

namespace Beacon.Crypt
{
    public class RsaPkcs8CryptoUtil
    {
        public RsaKey GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var keyPair = DotNetUtilities.GetRsaKeyPair(rsa);

                var key = new RsaKey
                {
                    Private = GeneratePrivateKey(keyPair.Private),
                    Public = GeneratePublicKey(keyPair.Public)
                };

                return key;
            }
        }

        public byte[] Sign(byte[] bytes, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var key = ParsePrivateKey(privateKey);
                rsa.ImportParameters(key);
                var signature = rsa.SignData(bytes, new MD5CryptoServiceProvider());
                return signature;
            }
        }

        public bool Verify(byte[] bytes, byte[] signature, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var key = ParsePublicKey(publicKey);
                rsa.ImportParameters(key);
                return rsa.VerifyData(bytes, new MD5CryptoServiceProvider(), signature);
            }
        }

        public byte[] Encrypt(byte[] plainBytes, string publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var key = ParsePublicKey(publicKey);
                rsa.ImportParameters(key);
                var encryptedBytes = rsa.Encrypt(plainBytes, false);
                return encryptedBytes;
            }
        }

        public byte[] Decrypt(byte[] encryptedBytes, string privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                var key = ParsePrivateKey(privateKey);
                rsa.ImportParameters(key);
                var decryptedBytes = rsa.Decrypt(encryptedBytes, false);
                return decryptedBytes;
            }
        }

        private static string GeneratePrivateKey(AsymmetricKeyParameter key)
        {
            var builder = new StringBuilder();

            using (var writer = new StringWriter(builder))
            {
                var pkcs8Gen = new Pkcs8Generator(key);
                var pemObj = pkcs8Gen.Generate();

                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(pemObj);
            }

            return builder.ToString();
        }

        private static string GeneratePublicKey(AsymmetricKeyParameter key)
        {
            var builder = new StringBuilder();

            using (var writer = new StringWriter(builder))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
            }

            return builder.ToString();
        }

        private static RSAParameters ParsePrivateKey(string privateKey)
        {
            using (var reader = new StringReader(privateKey))
            {
                var pemReader = new PemReader(reader);
                var key = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

                var parameter = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                    D = key.Exponent.ToByteArrayUnsigned(),
                    P = key.P.ToByteArrayUnsigned(),
                    Q = key.Q.ToByteArrayUnsigned(),
                    DP = key.DP.ToByteArrayUnsigned(),
                    DQ = key.DQ.ToByteArrayUnsigned(),
                    InverseQ = key.QInv.ToByteArrayUnsigned()
                };

                return parameter;
            }
        }

        private static RSAParameters ParsePublicKey(string publicKey)
        {
            using (var reader = new StringReader(publicKey))
            {
                var pemReader = new PemReader(reader);
                var key = (RsaKeyParameters)pemReader.ReadObject();

                var parameter = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(),
                    Exponent = key.Exponent.ToByteArrayUnsigned()
                };

                return parameter;
            }
        }
    }
}
