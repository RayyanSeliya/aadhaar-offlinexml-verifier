using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace aadhaar_offlinexml_verifier_console
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Aadhaar Offline XML Verifier");
            
            if (args.Length > 0 && (args[0] == "-h" || args[0] == "--help"))
            {
                DisplayHelp();
                return;
            }
            
            string xmlFilePath = string.Empty;
            string keyFilePath = string.Empty;
            
            // Check if arguments are provided
            if (args.Length > 0)
            {
                ProcessCommandLineArgs(args, ref xmlFilePath, ref keyFilePath);
            }
            else
            {
                ProcessInteractiveMode(ref xmlFilePath, ref keyFilePath);
            }
            
            // Verify the XML signature
            if (!string.IsNullOrEmpty(xmlFilePath) && !string.IsNullOrEmpty(keyFilePath))
            {
                VerifyXmlSignature(xmlFilePath, keyFilePath);
            }
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
        
        static void DisplayHelp()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  aadhaar-offlinexml-verifier-console [options]");
            Console.WriteLine("\nOptions:");
            Console.WriteLine("  -h, --help                 Show this help message");
            Console.WriteLine("  -x, --xml <path>           Path to XML file");
            Console.WriteLine("  -c, --cert <path>          Path to certificate file");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  aadhaar-offlinexml-verifier-console -x data.xml -c cert.cer");
            Console.WriteLine("  aadhaar-offlinexml-verifier-console data.xml cert.cer");
        }
        
        static void ProcessCommandLineArgs(string[] args, ref string xmlFilePath, ref string keyFilePath)
        {
            // Process named arguments
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "-x":
                    case "--xml":
                        if (i + 1 < args.Length) xmlFilePath = args[++i];
                        break;
                    case "-c":
                    case "--cert":
                        if (i + 1 < args.Length) keyFilePath = args[++i];
                        break;
                }
            }
            
            // Legacy support for positional arguments
            if (string.IsNullOrEmpty(xmlFilePath) && args.Length > 0)
            {
                string inputPath = args[0];
                
                if (Path.GetExtension(inputPath).ToLower() == ".xml")
                {
                    xmlFilePath = inputPath;
                    
                    // If certificate path is provided as second argument
                    if (args.Length > 1 && string.IsNullOrEmpty(keyFilePath))
                    {
                        keyFilePath = args[1];
                    }
                }
            }
            
            // Prompt for certificate if XML is provided but certificate is not
            if (!string.IsNullOrEmpty(xmlFilePath) && string.IsNullOrEmpty(keyFilePath))
            {
                Console.Write("Enter certificate file path: ");
                keyFilePath = Console.ReadLine();
            }
        }
        
        static void ProcessInteractiveMode(ref string xmlFilePath, ref string keyFilePath)
        {
            Console.Write("Enter XML file path: ");
            xmlFilePath = Console.ReadLine();
            
            Console.Write("Enter certificate file path: ");
            keyFilePath = Console.ReadLine();
        }
        
        static void VerifyXmlSignature(string xmlFilePath, string keyFilePath)
        {
            try
            {
                XmlDocument objXmlDocument = new XmlDocument();
                objXmlDocument.Load(xmlFilePath);
                
                string signatureValue = objXmlDocument.DocumentElement.ChildNodes[1].ChildNodes[1].InnerXml;
                XmlNode childElement = objXmlDocument.DocumentElement.ChildNodes[1];
                objXmlDocument.DocumentElement.RemoveChild(childElement);
                
                /*----------------Read and parse the public key as string-----------------------*/
                X509Certificate2 objX509Certificate2 = new X509Certificate2(keyFilePath, "public");
                Org.BouncyCastle.X509.X509Certificate objX509Certificate;
                X509CertificateParser objX509CertificateParser = new X509CertificateParser();
                objX509Certificate = objX509CertificateParser.ReadCertificate(objX509Certificate2.GetRawCertData());
                /*----------------End-----------------------*/
                
                /* Init alg */
                ISigner signer = SignerUtilities.GetSigner("SHA256withRSA");
                
                /* Populate key */
                signer.Init(false, objX509Certificate.GetPublicKey());
                
                /* Get the signature into bytes */
                var expectedSig = Convert.FromBase64String(signatureValue);
                
                /* Get the bytes to be signed from the string */
                var msgBytes = Encoding.UTF8.GetBytes(objXmlDocument.InnerXml);
                
                /* Calculate the signature and see if it matches */
                signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
                
                bool flag = signer.VerifySignature(expectedSig);
                
                if (flag)
                {
                    Console.WriteLine("XML Validated Successfully");
                    
                    // Display basic information from the XML
                    DisplayAadhaarInfo(objXmlDocument);
                }
                else
                {
                    Console.WriteLine("XML Validation Failed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verifying XML: {ex.Message}");
            }
        }
        
        static void DisplayAadhaarInfo(XmlDocument xmlDoc)
        {
            try
            {
                XmlNode poiNode = xmlDoc.SelectSingleNode("//OfflinePaperlessKyc/UidData/Poi");
                if (poiNode != null)
                {
                    Console.WriteLine("\nBasic Information:");
                    Console.WriteLine($"Name: {poiNode.Attributes["name"]?.Value}");
                    Console.WriteLine($"DOB: {poiNode.Attributes["dob"]?.Value}");
                    Console.WriteLine($"Gender: {poiNode.Attributes["gender"]?.Value}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error displaying Aadhaar info: {ex.Message}");
            }
        }
    }
}
