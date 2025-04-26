using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace aadhaar_offlinexml_verifier_console
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Aadhaar Offline XML Verifier");
            
            string xmlFilePath = string.Empty;
            string keyFilePath = string.Empty;
            string zipFilePath = string.Empty;
            string zipPassword = string.Empty;
            
            // Check if arguments are provided
            if (args.Length > 0)
            {
                string inputPath = args[0];
                
                if (Path.GetExtension(inputPath).ToLower() == ".zip")
                {
                    zipFilePath = inputPath;
                    
                    // If password is provided as second argument
                    if (args.Length > 1)
                    {
                        zipPassword = args[1];
                    }
                    else
                    {
                        Console.Write("Enter ZIP password (first 4 letters of name + YYYY): ");
                        zipPassword = Console.ReadLine();
                    }
                    
                    // Extract files from ZIP
                    var extractedFiles = ExtractAadhaarZip(zipFilePath, zipPassword);
                    xmlFilePath = extractedFiles.XmlPath;
                    keyFilePath = extractedFiles.CertPath;
                }
                else if (Path.GetExtension(inputPath).ToLower() == ".xml")
                {
                    xmlFilePath = inputPath;
                    
                    // If certificate path is provided as second argument
                    if (args.Length > 1)
                    {
                        keyFilePath = args[1];
                    }
                    else
                    {
                        Console.Write("Enter certificate file path: ");
                        keyFilePath = Console.ReadLine();
                    }
                }
            }
            else
            {
                Console.WriteLine("1. Verify XML file with certificate");
                Console.WriteLine("2. Process Aadhaar ZIP file");
                Console.Write("Choose option (1/2): ");
                
                string option = Console.ReadLine();
                
                if (option == "1")
                {
                    Console.Write("Enter XML file path: ");
                    xmlFilePath = Console.ReadLine();
                    
                    Console.Write("Enter certificate file path: ");
                    keyFilePath = Console.ReadLine();
                }
                else if (option == "2")
                {
                    Console.Write("Enter ZIP file path: ");
                    zipFilePath = Console.ReadLine();
                    
                    Console.Write("Enter ZIP password (first 4 letters of name + YYYY): ");
                    zipPassword = Console.ReadLine();
                    
                    // Extract files from ZIP
                    var extractedFiles = ExtractAadhaarZip(zipFilePath, zipPassword);
                    xmlFilePath = extractedFiles.XmlPath;
                    keyFilePath = extractedFiles.CertPath;
                }
                else
                {
                    Console.WriteLine("Invalid option selected.");
                    return;
                }
            }
            
            // Verify the XML signature
            if (!string.IsNullOrEmpty(xmlFilePath) && !string.IsNullOrEmpty(keyFilePath))
            {
                VerifyXmlSignature(xmlFilePath, keyFilePath);
            }
            
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
        
        static (string XmlPath, string CertPath) ExtractAadhaarZip(string zipPath, string password)
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "AadhaarVerifier_" + Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempDir);
            
            Console.WriteLine($"Extracting ZIP file to temporary directory: {tempDir}");
            
            try
            {
                // For password-protected ZIP, we need to use a different approach
                // Since System.IO.Compression doesn't support passwords, we'll use a workaround
                // by creating a temporary batch file to use 7-Zip if available
                
                if (!string.IsNullOrEmpty(password))
                {
                    string sevenZipPath = FindSevenZipPath();
                    
                    if (!string.IsNullOrEmpty(sevenZipPath))
                    {
                        // Use 7-Zip to extract
                        string batchFile = Path.Combine(Path.GetTempPath(), "extract_zip.bat");
                        File.WriteAllText(batchFile, $"\"{sevenZipPath}\" x \"{zipPath}\" -o\"{tempDir}\" -p{password} -y");
                        
                        var process = new System.Diagnostics.Process
                        {
                            StartInfo = new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = batchFile,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            }
                        };
                        
                        process.Start();
                        process.WaitForExit();
                        
                        File.Delete(batchFile);
                    }
                    else
                    {
                        Console.WriteLine("Warning: 7-Zip not found. Password-protected ZIP extraction may fail.");
                        ZipFile.ExtractToDirectory(zipPath, tempDir);
                    }
                }
                else
                {
                    ZipFile.ExtractToDirectory(zipPath, tempDir);
                }
                
                // Find XML and certificate files
                string xmlFile = Directory.GetFiles(tempDir, "*.xml").FirstOrDefault();
                string certFile = Directory.GetFiles(tempDir, "*.cer").FirstOrDefault();
                
                if (string.IsNullOrEmpty(xmlFile))
                {
                    throw new FileNotFoundException("XML file not found in the ZIP archive.");
                }
                
                if (string.IsNullOrEmpty(certFile))
                {
                    // If certificate is not in the ZIP, use the default UIDAI certificate
                    Console.WriteLine("Certificate not found in ZIP. Using default UIDAI certificate path.");
                    certFile = "uidai_offline_publickey_19062019.cer";
                    
                    if (!File.Exists(certFile))
                    {
                        Console.Write("Enter certificate file path: ");
                        certFile = Console.ReadLine();
                    }
                }
                
                Console.WriteLine($"Found XML file: {Path.GetFileName(xmlFile)}");
                Console.WriteLine($"Using certificate: {Path.GetFileName(certFile)}");
                
                return (xmlFile, certFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error extracting ZIP: {ex.Message}");
                throw;
            }
        }
        
        static string FindSevenZipPath()
        {
            string[] possiblePaths = {
                @"C:\Program Files\7-Zip\7z.exe",
                @"C:\Program Files (x86)\7-Zip\7z.exe"
            };
            
            foreach (string path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    return path;
                }
            }
            
            return null;
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
