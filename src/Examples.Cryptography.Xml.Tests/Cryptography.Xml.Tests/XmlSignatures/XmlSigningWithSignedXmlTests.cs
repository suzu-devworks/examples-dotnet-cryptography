using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Examples.Cryptography.Xml.Extensions;

namespace Examples.Cryptography.Tests.Xml;

/// <summary>
/// Examples for XML signing using SignedXml.
/// </summary>
/// <param name="fixture"></param>
/// <seealso href="https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.-ctor"/>
public class XmlSigningWithSignedXmlTests(
    XmlSigningWithSignedXmlTests.Fixture fixture
    ) : IClassFixture<XmlSigningWithSignedXmlTests.Fixture>
{
    public class Fixture : IAsyncLifetime
    {
        public ValueTask InitializeAsync()
        {
            return ValueTask.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            KeyPair.Dispose();
            GC.SuppressFinalize(this);
            return ValueTask.CompletedTask;
        }

        public RSA KeyPair { get; } = RSA.Create(2048);
    }

    private ITestOutputHelper? Output => TestContext.Current.TestOutputHelper;

    private void WriteStreamToOutput(Stream stream)
    {
        // Create a new XML document.
        XmlDocument doc = new XmlDocument();
        doc.Load(stream);

        Output?.WriteLine(doc.ToFormattedString(settings =>
        {
            settings.Indent = true;
        }));
    }

    /// <summary>
    /// This example shows how to sign and verify
    /// an entire XML document using an enveloped signature.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public void When_EntireXmlDocumentIsSigned_UsingEnvelopedSignature_Then_VerificationSuccessful()
    {
        using var exampleXmlStream = new MemoryStream();
        using var signedExampleXmlStream = new MemoryStream();

        // Generate a signing key.
        RSA key = fixture.KeyPair;

        // Create an XML file to sign.
        CreateSomeXml(exampleXmlStream);
        Output?.WriteLine("New XML file created.");

        // Sign the XML that was just created and save it in a
        // new file.
        SignXmlFile(new MemoryStream(exampleXmlStream.ToArray()), signedExampleXmlStream, key);
        Output?.WriteLine("XML file signed.");

        WriteStreamToOutput(new MemoryStream(signedExampleXmlStream.ToArray()));

        // Verify the signature of the signed XML.
        Output?.WriteLine("Verifying signature...");
        bool result = VerifyXmlFile(new MemoryStream(signedExampleXmlStream.ToArray()), key);

        // Display the results of the signature verification to
        // the console.
        if (result)
        {
            Output?.WriteLine("The XML signature is valid.");
        }
        else
        {
            Output?.WriteLine("The XML signature is not valid.");
            Assert.Fail("The XML signature is not valid.");
        }

        // Sign an XML file and save the signature in a new file. This method does not
        // save the public key within the XML file.  This file cannot be verified unless
        // the verifying code has the key with which it was signed.
        static void SignXmlFile(Stream fileStream, Stream signedFileStream, RSA key)
        {
            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Load the passed XML file using its name.
            doc.Load(new XmlTextReader(fileStream));

            // Create a SignedXml object.
            var signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = key;

            // Create a reference to be signed.
            var reference = new Reference();
            reference.Uri = "";

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
            XmlTextWriter writer = new XmlTextWriter(signedFileStream, new UTF8Encoding(false));
            doc.WriteTo(writer);
            writer.Close();
        }

        // Verify the signature of an XML file against an asymmetric
        // algorithm and return the result.
        static bool VerifyXmlFile(Stream fileStream, RSA key)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            xmlDocument.Load(fileStream);

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
        static void CreateSomeXml(Stream fileStream)
        {
            // Create a new XmlDocument object.
            var document = new XmlDocument();

            // Create a new XmlNode object.
            var node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");

            // Add some text to the node.
            node.InnerText = "Example text to be signed.";

            // Append the node to the document.
            document.AppendChild(node);

            // Save the XML document to the file name specified.
            XmlTextWriter writer = new XmlTextWriter(fileStream, new UTF8Encoding(false));
            document.WriteTo(writer);
            writer.Close();
        }
    }

    // /// <summary>
    // /// This example shows how to sign and verify
    // /// a Uniform Resource Identifier (URI) addressable object using a detached signature.
    // /// </summary>
    // [Fact]
    // public void When_UriAddressableObjectIsSigned_UsingDetachedSignature_Then_VerificationSuccessful()
    // {
    //     // The current implementation of .NET does not support detached signatures
    //     // due to security concerns, and always results in "Unable to resolve Uri {0}."
    //     // https://github.com/dotnet/dotnet/blob/182844eb5f91439e8daeb1dec252f95cb2436fa8/src/runtime/src/libraries/System.Security.Cryptography.Xml/src/System/Security/Cryptography/Xml/Reference.cs#L476
    // }

    /// <summary>
    /// This example shows how to sign and verify
    ///  a single element of an XML document using an enveloped signature.
    /// </summary>
    /// <remarks>
    /// Microsoft's explanation says 'using an enveloping signature' but what they're doing is 'enveloped signature'.
    /// </remarks>
    [Fact]
    public void When_SingleElementOfXmlDocumentIsSigned_UsingEnvelopedSignature_Then_VerificationSuccessful()
    {
        using var testXmlStream = new MemoryStream();
        using var signedExampleXmlStream = new MemoryStream();

        // Create an XML file to sign.
        CreateSomeXml(testXmlStream);
        Output?.WriteLine("New XML file created.");

        // Generate a signing key.
        RSA key = fixture.KeyPair;

        // Specify an element to sign.
        string[] elements = { "#tag1" };

        // Sign an XML file and save the signature to a
        // new file.
        SignXmlFile(new MemoryStream(testXmlStream.ToArray()), signedExampleXmlStream, key, elements);
        Output?.WriteLine("XML file signed.");

        WriteStreamToOutput(new MemoryStream(signedExampleXmlStream.ToArray()));

        // Verify the signature of the signed XML.
        Output?.WriteLine("Verifying signature...");

        bool result = VerifyXmlFile(new MemoryStream(signedExampleXmlStream.ToArray()));

        // Display the results of the signature verification to
        // the console.
        if (result)
        {
            Output?.WriteLine("The XML signature is valid.");
        }
        else
        {
            Output?.WriteLine("The XML signature is not valid.");
            Assert.Fail("The XML signature is not valid.");
        }

        // Sign an XML file and save the signature in a new file.
        static void SignXmlFile(Stream fileStream, Stream signedFileStream, RSA key, string[] elementsToSign)
        {
            // Check the arguments.
            ArgumentNullException.ThrowIfNull(fileStream);
            ArgumentNullException.ThrowIfNull(signedFileStream);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(elementsToSign);

            // Create a new XML document.
            XmlDocument doc = new XmlDocument();

            // Format the document to ignore white spaces.
            doc.PreserveWhitespace = false;

            // Load the passed XML file using it's name.
            doc.Load(new XmlTextReader(fileStream));

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(doc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = key;

            // Loop through each passed element to sign
            // and create a reference.
            foreach (string s in elementsToSign)
            {
                // Create a reference to be signed.
                Reference reference = new Reference();
                reference.Uri = s;

                // Add an enveloped transformation to the reference.
                XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                // Add the reference to the SignedXml object.
                signedXml.AddReference(reference);
            }

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue(key));
            signedXml.KeyInfo = keyInfo;

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
            XmlTextWriter writer = new XmlTextWriter(signedFileStream, new UTF8Encoding(false));
            doc.WriteTo(writer);
            writer.Close();
        }

        // Verify the signature of an XML file and return the result.
        static bool VerifyXmlFile(Stream fileStream)
        {
            // Check the arguments.
            ArgumentNullException.ThrowIfNull(fileStream);

            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Format using white spaces.
            xmlDocument.PreserveWhitespace = true;

            // Load the passed XML file into the document.
            xmlDocument.Load(fileStream);

            // Create a new SignedXml object and pass it
            // the XML document class.
            SignedXml signedXml = new SignedXml(xmlDocument);

            // Find the "Signature" node and create a new
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]!);

            // Check the signature and return the result.
            return signedXml.CheckSignature();
        }

        // Create example data to sign.
        static void CreateSomeXml(Stream stream)
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

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter writer = new XmlTextWriter(stream, new UTF8Encoding(false));
            document.WriteTo(writer);
            writer.Close();
        }
    }

    /// <summary>
    /// The following code example computes and XML signature.
    /// </summary>
    /// <remarks>
    /// I think this is the 'enveloping signature'.
    /// </remarks>
    /// <seealso href="https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml.addobject"/>
    [Fact]
    public void When_PieceOfXmlDocumentIsSigned__UsingDataObject_Then_VerificationSuccessful()
    {
        RSA key = fixture.KeyPair;

        // Create example data to sign.
        XmlDocument document = new XmlDocument();
        XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyElement", "samples");
        node.InnerText = "This is some text";
        document.AppendChild(node);
        Output?.WriteLine("Data to sign:\n" + document.OuterXml + "\n");

        // Create the SignedXml message.
        SignedXml signedXml = new SignedXml();
        signedXml.SigningKey = key;

        // Create a data object to hold the data to sign.
        DataObject dataObject = new DataObject();
        dataObject.Data = document.ChildNodes;
        dataObject.Id = "MyObjectId";

        // Add the data object to the signature.
        signedXml.AddObject(dataObject);

        // Create a reference to be able to package everything into the
        // message.
        Reference reference = new Reference();
        reference.Uri = "#MyObjectId";

        // Add the reference to the message.
        signedXml.AddReference(reference);

        // Add a KeyInfo.
        KeyInfo keyInfo = new KeyInfo();
        keyInfo.AddClause(new RSAKeyValue(key));
        signedXml.KeyInfo = keyInfo;

        // Compute the signature.
        signedXml.ComputeSignature();

        Output?.WriteLine("The data was signed.");

        // Here is my code after this.
        var signedXmlElement = signedXml.GetXml();
        Output?.WriteLine(signedXmlElement.ToFormattedString(settings =>
        {
            settings.Indent = true;
        }));

        bool result = Verify(signedXmlElement);
        Assert.True(result);

        static bool Verify(XmlElement xmlElement)
        {
            var xmlDocument = new XmlDocument()
            {
                PreserveWhitespace = true
            };
            xmlDocument.LoadXml(xmlElement.OuterXml);

            var nodeList = xmlDocument.GetElementsByTagName("Signature");
            var signedXml = new SignedXml(xmlDocument);
            signedXml.LoadXml((XmlElement)nodeList[0]!);

            return signedXml.CheckSignature();
        }
    }
}
