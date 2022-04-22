using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace ECDSA_Demo
{
    internal class Program
    {
        private const string PrivateKey = "-----BEGIN EC PRIVATE KEY-----\r\n"
         + "MDECAQEEIAB9mjPNUfIswmy/RTkHZw6Jb4LSFpaXBH0UmyU43mzPoAoGCCqGSM49\r\n"
         + "AwEH\r\n"
         + "-----END EC PRIVATE KEY-----\r\n";

        private const string PublicKey = "-----BEGIN PUBLIC KEY-----\r\n"
         + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyMhEXIWa5jP34bJ5H5qBZPo+7TwI\r\n"
         + "z9vD/hcCFohzA8ugFy52fASYWDOWZnJjEoNeM+5E6LcNXjaxLD3QOGhlxA==\r\n"
         + "-----END PUBLIC KEY-----\r\n";

        private const string LicenseSeparator = "|||";
        static void Main(string[] args)
        {
            var data = "\r\nServerId = 123456\r\n" +
                        "9724 	UI 25\r\n" +
                        "9726 	Mobile UI 10\r\n" +
                        "9728 	Operator App 3\r\n";

            GenerateLicense(data);


            ReadLicenseFromFile();

            Console.ReadLine();


        }

        private static void ReadLicenseFromFile()
        {
            // read license from file and parse it
            var licenseFromFile = File.ReadAllText("license.txt");
            var sigatureString = licenseFromFile.Split(LicenseSeparator)[0];
            byte[]? signatureFromFie = sigatureString.Split(" ").Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => (byte)int.Parse(i)).ToArray();
            var dataFromFie = licenseFromFile.Split(LicenseSeparator)[1];

            var verificationResult = Verify(dataFromFie, signatureFromFie, PublicKey);
            Console.WriteLine("============License from license.txt=================");
            Console.Write(licenseFromFile);
            Console.WriteLine("=======================================================");
            Console.WriteLine($"Verification result: {verificationResult}");
        }

        private static void GenerateLicense(string data)
        {
            // generate license and write it to file
            byte[]? signature = Sign(data);
            var signatureAsString = string.Empty;
            foreach (var @byte in signature)
            {
                signatureAsString += @byte.ToString() + " ";
            }
            var license = signatureAsString + LicenseSeparator + data;
            Console.WriteLine("============License has been generated=================");
            Console.Write(license);
            Console.WriteLine("=======================================================");
            File.WriteAllText("license.txt", license);
        }

        private static byte[] Sign(string data)
        {
            byte[]? signature;
            var messageAsByteArray = Encoding.ASCII.GetBytes(data);
            using (var reader = new StringReader(PrivateKey))
            {
                var pemReader = new PemReader(reader);
                var newPrivateKey = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                var privateKeyParameters = newPrivateKey.Private as ECPrivateKeyParameters;
                var signer = SignerUtilities.GetSigner("ECDSA");

                signer.Init(true, privateKeyParameters);
                signer.BlockUpdate(messageAsByteArray, 0, messageAsByteArray.Length);
                signature = signer.GenerateSignature();
            }

            return signature;
        }

        private static bool Verify(string message, byte[] signature, string publicKey)
        {
            var messageAsByteArray = Encoding.ASCII.GetBytes(message);

            using (var reader = new StringReader(PublicKey))
            {
                var pemReader = new PemReader(reader);
                var publicKeyParameters = pemReader.ReadObject() as ECPublicKeyParameters;

                var signer = SignerUtilities.GetSigner("ECDSA");
                signer.Init(false, publicKeyParameters);
                signer.BlockUpdate(messageAsByteArray, 0, messageAsByteArray.Length);

                return signer.VerifySignature(signature);
            }
        }

    }
}
