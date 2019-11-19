using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Math;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace RSASignAndVerify
{
    class Program
    {
        static void Main(string[] args)
        {
            string plainText = @"Hello. How Are You";            

            string signedData = Signature(plainText);
            Console.WriteLine("Signed text: {0}", signedData);
            var result = Verify(plainText, signedData);
            Console.WriteLine("Verified: {0}", result);
        }

        private static string Signature(string message)
        {
            string privateKeyPath = @"C:\Temp\EncryptionKeys\client_private_2048.pem";
            var privateRsa = RsaProviderFromPrivateKeyInPemFile(privateKeyPath);
            var signedData = privateRsa.SignData(Encoding.UTF8.GetBytes(message), CryptoConfig.MapNameToOID("SHA256"));

            return Convert.ToBase64String(signedData);
        }

        private static bool Verify(string message, string signedData)
        {
            string publicKeyPath = @"C:\Temp\EncryptionKeys\client_public_2048.pub";
            var publicRsa = RsaProviderFromPublicKeyInPemFile(publicKeyPath);
            var verifiedData = publicRsa.VerifyData(Encoding.UTF8.GetBytes(message), CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(signedData));

            return verifiedData;
        }       
        

        private static RSACryptoServiceProvider RsaProviderFromPrivateKeyInPemFile(string privateKeyPath)
        {
            using (TextReader privateKeyTextReader = new StringReader(File.ReadAllText(privateKeyPath)))
            {
                PemReader pr = new PemReader(privateKeyTextReader);
                AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                RSAParameters rsaParams = ToRSAParameters((RsaPrivateCrtKeyParameters)keyPair.Private);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }

        private static RSACryptoServiceProvider RsaProviderFromPublicKeyInPemFile(string publicKeyPath)
        {
            using (TextReader privateKeyTextReader = new StringReader(File.ReadAllText(publicKeyPath)))
            {
                PemReader pr = new PemReader(privateKeyTextReader);
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                RSAParameters rsaParams = ToRSAParameters((RsaKeyParameters)publicKey);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }
        private static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
            if (rsaKey.IsPrivate)
                rp.D = ConvertRSAParametersField(rsaKey.Exponent, rp.Modulus.Length);
            else
                rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
            return rp;
        }

        private static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
        {
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);

            return rp;

        }

        private static byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
            byte[] bs = n.ToByteArrayUnsigned();

            if (bs.Length == size)
                return bs;

            if (bs.Length > size)
                throw new ArgumentException("Specified size too small", "size");

            byte[] padded = new byte[size];
            Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
            return padded;
        }
        
    }
}
