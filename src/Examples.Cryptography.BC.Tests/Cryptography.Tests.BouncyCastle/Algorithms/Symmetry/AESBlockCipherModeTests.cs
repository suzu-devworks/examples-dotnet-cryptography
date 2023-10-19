using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Examples.Cryptography.Tests.BouncyCastle.Algorithms.Symmetry;

public class AESBlockCipherModeTests
{
    [Fact]
    public void WhenEncrypting_WithECB()
    {
        var inputText = "Here is some data to encrypt!";

        ICipherParameters keyParam = KeyParameterGeneration(keySize: 256);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        static byte[] Encrypt(ICipherParameters keyParam, byte[] plainTextData)
        {
            // First choose the "engine", in this case AES
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();
            // Next select the mode compatible with the "engine", in this case we use the simple ECB mode
            IBlockCipherMode symmetricBlockMode = new EcbBlockCipher(symmetricBlockCipher);
            // Finally select a compatible padding, PKCS7 which is the default
            IBlockCipherPadding padding = new Pkcs7Padding();

            PaddedBufferedBlockCipher ecbCipher = new(symmetricBlockMode, padding);
            // apply the mode and engine on the plainTextData
            ecbCipher.Init(true, keyParam);

            int blockSize = ecbCipher.GetBlockSize();
            int outputSize = ecbCipher.GetOutputSize(plainTextData.Length);

            // byte[] cipherTextData = new byte[outputSize];
            // // process a block of bytes from in putting the result into out.
            // int processLength = ecbCipher.ProcessBytes(plainTextData, 0, dataSize, cipherTextData, 0);
            // // Finish the operation.
            // int finalLength = ecbCipher.DoFinal(cipherTextData, processLength);
            // byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)];
            // Array.Copy(cipherTextData, 0, finalCipherTextData, 0, finalCipherTextData.Length);
            Span<byte> cipherTextData = stackalloc byte[outputSize];
            var processLength = ecbCipher.ProcessBytes(plainTextData.AsSpan(), cipherTextData);
            int finalLength = ecbCipher.DoFinal(cipherTextData[processLength..]);
            int length = outputSize - (blockSize - finalLength);
            byte[] finalCipherTextData = cipherTextData[..length].ToArray();

            return finalCipherTextData;
        }

        static byte[] Decrypt(ICipherParameters keyParam, byte[] cipherTextData)
        {
            // First choose the "engine", in this case AES
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();
            // Next select the mode compatible with the "engine", in this case we use the simple ECB mode
            IBlockCipherMode symmetricBlockMode = new EcbBlockCipher(symmetricBlockCipher);
            // Finally select a compatible padding, PKCS7 which is the default
            IBlockCipherPadding padding = new Pkcs7Padding();

            PaddedBufferedBlockCipher ecbCipher = new(symmetricBlockMode, padding);
            // apply the mode and engine on the plainTextData
            ecbCipher.Init(false, keyParam);

            int blockSize = ecbCipher.GetBlockSize();
            int outputSize = ecbCipher.GetOutputSize(cipherTextData.Length);

            // byte[] plainTextData = new byte[outputSize];
            // int processLength = ecbCipher.ProcessBytes(cipherTextData, 0, cipherTextData.Length, plainTextData, 0);
            // int finalLength = ecbCipher.DoFinal(plainTextData, processLength);
            // byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)];
            // Array.Copy(plainTextData, 0, finalPlainTextData, 0, finalPlainTextData.Length);
            Span<byte> plainTextData = stackalloc byte[outputSize];
            var processLength = ecbCipher.ProcessBytes(cipherTextData.AsSpan(), plainTextData);
            int finalLength = ecbCipher.DoFinal(plainTextData[processLength..]);
            int length = outputSize - (blockSize - finalLength);
            byte[] finalPlainTextData = plainTextData[..length].ToArray();

            return finalPlainTextData;
        }
    }


    [Fact]
    public void WhenEncrypting_WithCBC()
    {
        var inputText = "Here is some data to encrypt!";
        byte[] iv = Random.GenerateSeed(16); // need random.

        ICipherParameters keyParam = KeyParameterGenerationWithIV(keySize: 256, iv);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        static byte[] Encrypt(ICipherParameters keyParamWithIV, byte[] plainTextData)
        {
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();
            IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(symmetricBlockCipher);
            IBlockCipherPadding padding = new Pkcs7Padding();

            PaddedBufferedBlockCipher cbcCipher = new(symmetricBlockMode, padding);
            cbcCipher.Init(true, keyParamWithIV);

            int blockSize = cbcCipher.GetBlockSize();
            int outputSize = cbcCipher.GetOutputSize(plainTextData.Length);

            byte[] cipherTextData = new byte[outputSize];
            int processLength = cbcCipher.ProcessBytes(plainTextData, 0, plainTextData.Length, cipherTextData, 0);
            int finalLength = cbcCipher.DoFinal(cipherTextData, processLength);
            byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)];
            Array.Copy(cipherTextData, 0, finalCipherTextData, 0, finalCipherTextData.Length);

            return finalCipherTextData;
        }

        static byte[] Decrypt(ICipherParameters keyParamWithIV, byte[] cipherTextData)
        {
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();
            IBlockCipherMode symmetricBlockMode = new CbcBlockCipher(symmetricBlockCipher);
            IBlockCipherPadding padding = new Pkcs7Padding();

            PaddedBufferedBlockCipher cbcCipher = new(symmetricBlockMode, padding);
            cbcCipher.Init(false, keyParamWithIV);

            int blockSize = cbcCipher.GetBlockSize();
            int outputSize = cbcCipher.GetOutputSize(cipherTextData.Length);

            byte[] plainTextData = new byte[outputSize];
            int processLength = cbcCipher.ProcessBytes(cipherTextData, 0, cipherTextData.Length, plainTextData, 0);
            int finalLength = cbcCipher.DoFinal(plainTextData, processLength);
            byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)];
            Array.Copy(plainTextData, 0, finalPlainTextData, 0, finalPlainTextData.Length);

            return finalPlainTextData;
        }
    }


    [Fact]
    public void WhenEncrypting_WithCFBStream()
    {
        var inputText = "Here is some data to encrypt!";
        byte[] iv = Random.GenerateSeed(1); // need random.

        ICipherParameters keyParam = KeyParameterGenerationWithIV(keySize: 128, iv);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        static byte[] Encrypt(ICipherParameters keyParamWithIV, byte[] plainTextData)
        {
            IBlockCipher symmetricBlockCipher = new IdeaEngine();

            // Next select the mode compatible with the "engine", in this case we
            // use CFB mode as a streaming cipher - set the block size to 1 byte
            IBlockCipherMode symmetricBlockMode = new CfbBlockCipher(symmetricBlockCipher, 8);

            StreamBlockCipher cfbCipher = new(symmetricBlockMode);
            cfbCipher.Init(true, keyParamWithIV);

            byte[] cipherTextData = new byte[plainTextData.Length];
            // simulate stream
            for (int j = 0; j < plainTextData.Length; j++)
            {
                cipherTextData[j] = cfbCipher.ReturnByte(plainTextData[j]);
            }

            return cipherTextData;
        }

        static byte[] Decrypt(ICipherParameters keyParamWithIV, byte[] cipherTextData)
        {
            IBlockCipher symmetricBlockCipher = new IdeaEngine();

            // Next select the mode compatible with the "engine", in this case we
            // use CFB mode as a streaming cipher - set the block size to 1 byte
            IBlockCipherMode symmetricBlockMode = new CfbBlockCipher(symmetricBlockCipher, 8);

            StreamBlockCipher cfbCipher = new(symmetricBlockMode);
            cfbCipher.Init(false, keyParamWithIV);

            byte[] plainTextData = new byte[cipherTextData.Length];
            // simulate stream
            for (int j = 0; j < plainTextData.Length; j++)
            {
                plainTextData[j] = cfbCipher.ReturnByte(cipherTextData[j]);
            }

            return plainTextData;
        }
    }


    [Fact]
    public void WhenEncrypting_WithCTRWithoutPadding()
    {
        var inputText = "Here is some data to encrypt!";
        byte[] iv = Random.GenerateSeed(16); // need random.

        ICipherParameters keyParam = KeyParameterGenerationWithIV(keySize: 256, iv);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        static byte[] Encrypt(ICipherParameters keyParamWithIV, byte[] plainTextData)
        {
            IBlockCipher symmetricBlockCipher = new ThreefishEngine(256);
            IBlockCipherMode symmetricBlockMode = new KCtrBlockCipher(symmetricBlockCipher);

            BufferedBlockCipher ctrCipher = new(symmetricBlockMode);
            ctrCipher.Init(true, keyParamWithIV);

            int blockSize = ctrCipher.GetBlockSize();
            int outputSize = ctrCipher.GetOutputSize(plainTextData.Length);

            byte[] cipherTextData = new byte[outputSize];
            int processLength = ctrCipher.ProcessBytes(plainTextData, 0, plainTextData.Length, cipherTextData, 0);
            int finalLength = ctrCipher.DoFinal(cipherTextData, processLength);
            byte[] finalCipherTextData = new byte[cipherTextData.Length - (blockSize - finalLength)];
            Array.Copy(cipherTextData, 0, finalCipherTextData, 0, finalCipherTextData.Length);

            return cipherTextData;
        }

        static byte[] Decrypt(ICipherParameters keyParamWithIV, byte[] cipherTextData)
        {
            IBlockCipher symmetricBlockCipher = new ThreefishEngine(256);
            IBlockCipherMode symmetricBlockMode = new KCtrBlockCipher(symmetricBlockCipher);

            BufferedBlockCipher ctrCipher = new(symmetricBlockMode);
            ctrCipher.Init(false, keyParamWithIV);

            int blockSize = ctrCipher.GetBlockSize();
            int outputSize = ctrCipher.GetOutputSize(cipherTextData.Length);

            byte[] plainTextData = new byte[outputSize];
            int processLength = ctrCipher.ProcessBytes(cipherTextData, 0, cipherTextData.Length, plainTextData, 0);
            int finalLength = ctrCipher.DoFinal(plainTextData, processLength);
            byte[] finalPlainTextData = new byte[plainTextData.Length - (blockSize - finalLength)];
            Array.Copy(plainTextData, 0, finalPlainTextData, 0, finalPlainTextData.Length);

            return plainTextData;
        }
    }


    [Fact]
    public void WhenEncrypting_WithCCMAEADWithoutPadding()
    {
        var inputText = "Here is some data to encrypt!";

        byte[] sampleIVnonce = Random.GenerateSeed(16); // need random.
        byte[] additionalAuthenticatedDataA
            = Encoding.UTF8.GetBytes("This message was sent 29th Feb at 11.00am - does not repeat");

        KeyParameter keyParam = (KeyParameter)KeyParameterGeneration(keySize: 256);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        byte[] Encrypt(KeyParameter keyParam, byte[] plainTextData)
        {
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();

            int macSize = 8 * symmetricBlockCipher.GetBlockSize();
            byte[] nonce = new byte[12];
            byte[] associatedText = additionalAuthenticatedDataA;
            Array.Copy(sampleIVnonce, nonce, nonce.Length);

            AeadParameters keyParamAead = new(keyParam, macSize, nonce, associatedText);

            CcmBlockCipher cipherMode = new(symmetricBlockCipher);
            cipherMode.Init(true, keyParamAead);

            cipherMode.ProcessBytes(plainTextData, 0, plainTextData.Length, null, 0);

            int outputSize = cipherMode.GetOutputSize(0);
            byte[] cipherTextData = new byte[outputSize];
            cipherMode.DoFinal(cipherTextData, 0);

            return cipherTextData;
        }

        byte[] Decrypt(KeyParameter keyParam, byte[] cipherTextData)
        {
            //IBlockCipher symmetricBlockCipher = new AesEngine();
            IBlockCipher symmetricBlockCipher = AesUtilities.CreateEngine();

            int macSize = 8 * symmetricBlockCipher.GetBlockSize();
            byte[] nonce = new byte[12];
            byte[] associatedText = additionalAuthenticatedDataA;
            Array.Copy(sampleIVnonce, nonce, nonce.Length);

            AeadParameters keyParamAead = new(keyParam, macSize, nonce, associatedText);

            CcmBlockCipher cipherMode = new(symmetricBlockCipher);
            cipherMode.Init(false, keyParamAead);

            cipherMode.ProcessBytes(cipherTextData, 0, cipherTextData.Length, null, 0);

            int outputSize = cipherMode.GetOutputSize(0);
            byte[] plainTextData = new byte[outputSize];
            cipherMode.DoFinal(plainTextData, 0);

            return plainTextData;
        }
    }


    [Fact]
    public void WhenEncrypting_WithGCMAEAD()
    {
        var inputText = "Here is some data to encrypt!";

        byte[] sampleIVnonce = Random.GenerateSeed(16); // need random.
        byte[] additionalAuthenticatedDataA
            = Encoding.UTF8.GetBytes("This message was sent 29th Feb at 11.00am - does not repeat");

        KeyParameter keyParam = (KeyParameter)KeyParameterGeneration(keySize: 256);

        // Encrypts or decrypts data in a single-part operation.
        var input = Encoding.UTF8.GetBytes(inputText);
        var encripted = Encrypt(keyParam, input);

        byte[] decripted = Decrypt(keyParam, encripted);
        var outputText = Encoding.UTF8.GetString(decripted);

        outputText.Is(inputText, "failed");

        return;

        byte[] Encrypt(KeyParameter keyParam, byte[] plainTextData)
        {
            //IBlockCipher cipher = new AesEngine();
            IBlockCipher cipher = AesUtilities.CreateEngine();

            int macSize = 8 * cipher.GetBlockSize();
            byte[] nonce = sampleIVnonce;
            byte[] associatedText = additionalAuthenticatedDataA;

            AeadParameters keyParamAead = new(keyParam, macSize, nonce, associatedText);

            GcmBlockCipher cipherMode = new(cipher);
            cipherMode.Init(true, keyParamAead);

            int outputSize = cipherMode.GetOutputSize(plainTextData.Length);

            byte[] cipherTextData = new byte[outputSize];
            int result = cipherMode.ProcessBytes(plainTextData, 0, plainTextData.Length, cipherTextData, 0);
            cipherMode.DoFinal(cipherTextData, result);

            return cipherTextData;
        }

        byte[] Decrypt(KeyParameter keyParam, byte[] cipherTextData)
        {
            //IBlockCipher cipher = new AesEngine();
            IBlockCipher cipher = AesUtilities.CreateEngine();

            int macSize = 8 * cipher.GetBlockSize();
            byte[] nonce = sampleIVnonce;
            byte[] associatedText = additionalAuthenticatedDataA;

            AeadParameters keyParamAead = new(keyParam, macSize, nonce, associatedText);

            GcmBlockCipher cipherMode = new(cipher);
            cipherMode.Init(false, keyParamAead);

            int outputSize = cipherMode.GetOutputSize(cipherTextData.Length);
            byte[] plainTextData = new byte[outputSize];
            int result = cipherMode.ProcessBytes(cipherTextData, 0, cipherTextData.Length, plainTextData, 0);
            cipherMode.DoFinal(plainTextData, result);

            return plainTextData;
        }
    }

    private static readonly SecureRandom Random = new();

    private static ICipherParameters KeyParameterGeneration(int keySize)
    {
        CipherKeyGenerator keyGen = new();
        keyGen.Init(new KeyGenerationParameters(Random, keySize));
        KeyParameter keyParam = keyGen.GenerateKeyParameter();
        return keyParam;
    }

    public static ParametersWithIV KeyParameterGenerationWithIV(int keySize, byte[] iv)
    {
        CipherKeyGenerator keyGen = new();
        keyGen.Init(new KeyGenerationParameters(Random, keySize));
        KeyParameter keyParam = keyGen.GenerateKeyParameter();
        ParametersWithIV keyParamWithIV = new(keyParam, iv);
        return keyParamWithIV;
    }

}
