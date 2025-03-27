using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Examples.Cryptography.Xml;

namespace Examples.Cryptography.Tests.Xml;

public class XmlSigningUsingMSDocsTests : IClassFixture<XmlDataFixture>
{
    private readonly ITestOutputHelper _output;
    private readonly XmlDataFixture _fixture;

    public XmlSigningUsingMSDocsTests(XmlDataFixture fixture, ITestOutputHelper output)
    {
        /// ```shell
        /// dotnet test --logger "console;verbosity=detailed"
        /// ```
        _output = output;
        _fixture = fixture;
    }


    [Fact]
    public void WhenDoingSignAndValidateEntireXMLDocument_UsingEnvelopedSignature()
    {
        // see.
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml?view=dotnet-plat-ext-7.0

        // Generate a signing key.
        //RSA key = RSA.Create();
        RSA key = _fixture.RSASigner.GetRSAPrivateKey()!;

        // Create an XML file to sign.
        var xml = CreateSomeXml("Example.xml");
        _output.WriteLine("New XML file created.");

        // Sign the XML that was just created and save it in a
        // new file.
        var signed = SignXmlFile("Example.xml", "signedExample.xml", key, xml);
        _output.WriteLine("XML file signed.");
        _output.WriteLine($"xml:{Environment.NewLine}{signed!.ToFormattedOuterXml()}");

        // Verify the signature of the signed XML.
        _output.WriteLine("Verifying signature...");

        bool result = VerifyXmlFile("SignedExample.xml", key, signed);
        result.IsTrue("The XML signature is not valid.");



        // Sign an XML file and save the signature in a new file. This method does not
        // save the public key within the XML file.  This file cannot be verified unless
        // the verifying code has the key with which it was signed.
        static XmlDocument SignXmlFile(string fileName, string signedFileName, RSA key, XmlDocument xml)
        {
            // Create a new XML document.
            var doc = new XmlDocument();

            // Load the passed XML file using its name.
            //doc.Load(new XmlTextReader(fileName));
            doc.LoadXml(xml.OuterXml);

            // Create a SignedXml object.
            var signedXml = new SignedXml(doc)
            {
                // Add the key to the SignedXml document.
                SigningKey = key
            };

            // Create a reference to be signed.
            var reference = new Reference(uri: "");

            // Add an enveloped transformation to the reference.
            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement!.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            // Save the signed XML document to a file specified
            // using the passed string.
            // XmlTextWriter writer = new XmlTextWriter(signedFileName, new UTF8Encoding(false));
            // doc.WriteTo(writer);
            // writer.Close();

            return doc;
        }

        // Verify the signature of an XML file against an asymmetric
        // algorithm and return the result.
        static Boolean VerifyXmlFile(string _, RSA key, XmlDocument xmlDocument)
        {
            // Create a new XML document.
            //XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            //xmlDocument.Load(name);
            //xmlDocument.LoadXml(xml);

            // Create a new SignedXml object and pass it
            // the XML document class.
            var signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]!);

            // Check the signature and return the result.
            return signedXml.CheckSignature(key);
        }

        // Create example data to sign.
        static XmlDocument CreateSomeXml(string _)
        {
            // Create a new XmlDocument object.
            var document = new XmlDocument();

            // Create a new XmlNode object.
            var node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");

            // Add some text to the node.
            //node.InnerText = "Example text to be signed.";
            var content = document.CreateElement("Content");
            content.InnerText = "Example text to be signed.";
            node.AppendChild(content);

            // Append the node to the document.
            document.AppendChild(node);

            // Save the XML document to the file name specified.
            // XmlTextWriter writer = new XmlTextWriter(FileName, new UTF8Encoding(false));
            // document.WriteTo(writer);
            // writer.Close();

            return document;
        }
    }

    [Fact]
    public void WhenDoingSignAndValidateSomeElementOfXMLDocument_UsingEnvelopingSignature()
    {
        // see.
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml?view=dotnet-plat-ext-7.0

        // Generate a signing key.
        // RSA key = RSA.Create();
        RSA key = _fixture.RSASigner.GetRSAPrivateKey()!;

        // Create an XML file to sign.
        var xml = CreateSomeXml();
        _output.WriteLine("New XML file created.");

        // Specify an element to sign.
        string[] elements = { "#tag1", "#tag3" };

        // Sign an XML file and save the signature to a
        // new file.
        var signed = SignXmlFile("Test.xml", "SignedExample.xml", key, elements, xml);
        _output.WriteLine("XML file signed.");
        _output.WriteLine($"xml:{Environment.NewLine}{signed!.ToFormattedOuterXml()}");

        // Verify the signature of the signed XML.
        _output.WriteLine("Verifying signature...");

        bool result = VerifyXmlFile("SignedExample.xml", signed);
        result.IsTrue("The XML signature is not valid.");



        // Sign an XML file and save the signature in a new file.
        static XmlDocument SignXmlFile(string fileName, string signedFileName, RSA key, string[] elementsToSign, XmlDocument xml)
        {
            // Check the arguments.
            // if (FileName == null)
            //     throw new ArgumentNullException("FileName");
            // if (SignedFileName == null)
            //     throw new ArgumentNullException("SignedFileName");
            // if (key == null)
            //     throw new ArgumentNullException("Key");
            // if (elementsToSign == null)
            //     throw new ArgumentNullException("ElementsToSign");

            // Create a new XML document.
            var doc = new XmlDocument
            {
                // Format the document to ignore white spaces.
                PreserveWhitespace = false
            };

            // Load the passed XML file using it's name.
            //doc.Load(new XmlTextReader(fileName));
            doc.LoadXml(xml.OuterXml);

            // Create a SignedXml object.
            var signedXml = new SignedXml(doc)
            {
                // Add the key to the SignedXml document.
                SigningKey = key
            };

            // Loop through each passed element to sign
            // and create a reference.
            foreach (string s in elementsToSign)
            {
                // Create a reference to be signed.
                var reference = new Reference(uri: s);

                // Add an enveloped transformation to the reference.
                var env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                //# Add an exclusive C14N XML canonicalization transform.
                var execC14N = new XmlDsigExcC14NTransform();
                reference.AddTransform(execC14N);

                // Add the reference to the SignedXml object.
                signedXml.AddReference(reference);
            }

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue(key));
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            doc.DocumentElement!.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            // if (doc.FirstChild is XmlDeclaration)
            // {
            //     doc.RemoveChild(doc.FirstChild);
            // }

            // Save the signed XML document to a file specified
            // using the passed string.
            // XmlTextWriter writer = new XmlTextWriter(signedFileName, new UTF8Encoding(false));
            // doc.WriteTo(writer);
            // writer.Close();

            return doc;
        }

        // Verify the signature of an XML file and return the result.
        static Boolean VerifyXmlFile(string _, XmlDocument xml)
        {
            // Check the arguments.
            // if (name == null)
            //     throw new ArgumentNullException("Name");

            // Create a new XML document.
            var xmlDocument = new XmlDocument
            {
                // Format using white spaces.
                PreserveWhitespace = true
            };

            // Load the passed XML file into the document.
            //xmlDocument.Load(name);
            xmlDocument.LoadXml(xml.OuterXml);

            // Create a new SignedXml object and pass it
            // the XML document class.
            var signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]!);

            // Check the signature and return the result.
            return signedXml.CheckSignature();
        }

        // Create example data to sign.
        static XmlDocument CreateSomeXml()
        {
            // Create a new XmlDocument object.
            var document = new XmlDocument();

            // Create a new XmlNode object.
            XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");
            document.AppendChild(node);

            XmlElement branch1 = document.CreateElement("", "MyBranch", "samples");
            branch1.SetAttribute("id", "tag1");
            node.AppendChild(branch1);

            XmlNode leaf1 = document.CreateNode(XmlNodeType.Element, "", "MyLeaf", "samples");
            leaf1.InnerText = "Example text to be signed.";
            branch1.AppendChild(leaf1);

            XmlElement branch2 = document.CreateElement("", "MyBranch", "samples");
            branch2.SetAttribute("id", "tag2");
            node.AppendChild(branch2);

            XmlNode leaf21 = document.CreateNode(XmlNodeType.Element, "", "MyLeaf", "samples");
            leaf21.InnerText = "Don't sign here.";
            node.AppendChild(leaf21);
            node.AppendChild(leaf21.Clone());
            node.AppendChild(leaf21.Clone());

            XmlElement branch3 = document.CreateElement("", "MyBranch", "samples");
            branch3.SetAttribute("id", "tag3");
            node.AppendChild(branch3);

            return document;
        }

    }


    [Fact]
    public void WhenDoingSignAndValidateDataObject()
    {
        // see.
        // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.addobject?view=dotnet-plat-ext-7.0

        // Generate a signing key.
        //RSA Key = RSA.Create();
        RSA key = _fixture.RSASigner.GetRSAPrivateKey()!;

        // Create example data to sign.
        XmlDocument document = CreateSomeXml();
        _output.WriteLine("Data to sign:\n" + document.OuterXml + "\n");

        // Create the SignedXml message.
        var signedXml = new SignedXml
        {
            SigningKey = key
        };

        // Create a data object to hold the data to sign.
        var dataObject = new DataObject
        {
            Data = document.ChildNodes,
            Id = "MyObjectId"
        };

        // Add the data object to the signature.
        signedXml.AddObject(dataObject);

        // Create a reference to be able to package everything into the
        // message.
        var reference = new Reference(uri: "#MyObjectId");

        // Add the reference to the message.
        signedXml.AddReference(reference);

        // Add a KeyInfo.
        var keyInfo = new KeyInfo() { Id = "MyKeyInfoId" };
        keyInfo.AddClause(new RSAKeyValue(key));
        signedXml.KeyInfo = keyInfo;

        // Compute the signature.
        signedXml.ComputeSignature();

        // Get the XML representation of the signature and save
        // it to an XmlElement object.
        XmlElement xmlDigitalSignature = signedXml.GetXml();

        _output.WriteLine("The data was signed.");
        _output.WriteLine($"xml:{Environment.NewLine}{xmlDigitalSignature.ToFormattedOuterXml()}");

        bool result = Verify(xmlDigitalSignature);
        result.IsTrue("The XML signature is not valid.");



        static bool Verify(XmlNode xml)
        {
            var xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            xmlDocument.LoadXml(xml.OuterXml);

            var nodeList = xmlDocument.GetElementsByTagName("Signature");

            var signedXml = new SignedXml(xmlDocument);
            signedXml.LoadXml((XmlElement)nodeList[0]!);

            return signedXml.CheckSignature();
        }

        static XmlDocument CreateSomeXml()
        {
            var document = new XmlDocument();
            XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");
            //node.InnerText = "This is some text";
            document.AppendChild(node);

            XmlElement content = document.CreateElement("Content");
            content.InnerText = "This is some text.";
            node.AppendChild(content);

            return document;
        }

    }

}
