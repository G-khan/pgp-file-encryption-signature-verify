package securepgp.pgp

import org.bouncycastle.bcpg.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRingCollection
import org.bouncycastle.openpgp.operator.jcajce.*
import java.io.*
import java.lang.Exception
import java.security.Provider
import java.security.SecureRandom
import java.security.Security

object PgpHelper {

    const val BC = "BC"

    private fun getProvider(): Provider {
        var provider: Provider? = Security.getProvider(BC)
        if (provider == null) {
            provider = BouncyCastleProvider()
            Security.addProvider(provider)
        }
        return provider
    }

    @Throws(IOException::class, PGPException::class)
    fun readPublicKey(inputStream: InputStream?): PGPPublicKey? {
        val decodedInputStream = PGPUtil.getDecoderStream(inputStream)
        val pgpPublicKeyCollection: PGPPublicKeyRingCollection = BcPGPPublicKeyRingCollection(decodedInputStream)

        var key: PGPPublicKey? = null

        val keyRingsIt = pgpPublicKeyCollection.keyRings
        while (key == null && keyRingsIt.hasNext()) {
            val keyRing = keyRingsIt.next() as PGPPublicKeyRing
            val publicKeysIt = keyRing.publicKeys
            while (key == null && publicKeysIt.hasNext()) {
                val pgpPublicKey = publicKeysIt.next() as PGPPublicKey
                if (pgpPublicKey.isEncryptionKey) {
                    key = pgpPublicKey
                }
            }
        }
        requireNotNull(key) { "Can't find encryption key in key ring." } //@TODO
        return key
    }


    /**
     * Load a secret key ring collection from keyIn and find the secret key corresponding to
     * keyID if it exists.
     *
     * @param keyIn input stream representing a key ring collection.
     * @param keyID keyID we want.
     * @param pass  passphrase to decrypt secret key with.
     * @return privateKey
     */
    @Throws(IOException::class, PGPException::class)
    fun findSecretKey(keyIn: InputStream, keyID: Long, pass: CharArray): PGPPrivateKey? {
        val pgpSec: PGPSecretKeyRingCollection = BcPGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn))
        val pgpSecKey = pgpSec.getSecretKey(keyID) ?: return null
        val decryptor = JcePBESecretKeyDecryptorBuilder(JcaPGPDigestCalculatorProviderBuilder().setProvider(BC).build()).setProvider(BC).build(pass)
        return pgpSecKey.extractPrivateKey(decryptor)
    }


    /**
     * decrypt the passed in message stream
     */
    @Throws(Exception::class)
    fun decryptFile(inputStream: InputStream, outputStream: OutputStream, keyIn: InputStream, passwd: CharArray) {
        this.getProvider()
        val decodedInputStream = PGPUtil.getDecoderStream(inputStream)
        val pgpFactory: PGPObjectFactory = BcPGPObjectFactory(decodedInputStream)
        val encryptedDataList: PGPEncryptedDataList
        val pgpObject = pgpFactory.nextObject()
        //
        // the first object might be a PGP marker packet.
        //
        encryptedDataList = if (pgpObject is PGPEncryptedDataList) {
            pgpObject
        } else {
            pgpFactory.nextObject() as PGPEncryptedDataList
        }

        //
        // find the secret key
        //
        val it: Iterator<PGPPublicKeyEncryptedData> = encryptedDataList.encryptedDataObjects as Iterator<PGPPublicKeyEncryptedData>
        var pgpPrivateKey: PGPPrivateKey? = null
        var keyEncryptedData: PGPPublicKeyEncryptedData? = null

        while (pgpPrivateKey == null && it.hasNext()) {
            keyEncryptedData = it.next()
            pgpPrivateKey = findSecretKey(keyIn, keyEncryptedData.keyID, passwd)
        }

        if (pgpPrivateKey == null || keyEncryptedData == null) {
            throw IllegalArgumentException("Secret key for message not found.");
        }

        val keyDataDecryptorFactory = JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BC).setContentProvider(BC).build(pgpPrivateKey)
        val clear = keyEncryptedData.getDataStream(keyDataDecryptorFactory)
        val plainFact: PGPObjectFactory = BcPGPObjectFactory(clear)
        var message = plainFact.nextObject()
        if (message is PGPCompressedData) {
            val pgpObjectFactory: PGPObjectFactory = BcPGPObjectFactory(message.dataStream)
            message = pgpObjectFactory.nextObject()
        }
        when (message) {
            is PGPLiteralData -> {
                val dataInputStream = message.inputStream
                var byteValue: Int
                while ((dataInputStream.read().also { byteValue = it }) >= 0) {
                    outputStream.write(byteValue)
                }
            }


            is PGPOnePassSignatureList -> {
                throw PGPException("Encrypted message contains a signed message - not literal data.")
            }
            else -> {
                throw PGPException("Message is not a simple encrypted file - type unknown.")
            }
        }

        if (keyEncryptedData.isIntegrityProtected && !keyEncryptedData.verify()) {
            throw PGPException("Message failed integrity check")
        }
    }


    @Throws(IOException::class)
    fun encryptFile(out: OutputStream, fileName: String, encKey: PGPPublicKey, armor: Boolean, withIntegrityCheck: Boolean) {
        var output = out
        this.getProvider()
        if (armor) {
            output = ArmoredOutputStream(output)
        }
        val byteOutStream = ByteArrayOutputStream()
        val compressedData = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
        PGPUtil.writeFileToLiteralData(
            compressedData.open(byteOutStream),
            PGPLiteralData.BINARY, File(fileName)
        )
        compressedData.close()
        val encryptorBuilder = JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setWithIntegrityPacket(withIntegrityCheck)
            .setSecureRandom(
                SecureRandom()
            ).setProvider(BC)
        val encryptedDataGenerator = PGPEncryptedDataGenerator(encryptorBuilder)
        val encryptionMethodGenerator = JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(BouncyCastleProvider()).setSecureRandom(
            SecureRandom()
        )
        encryptedDataGenerator.addMethod(encryptionMethodGenerator)
        val bytes = byteOutStream.toByteArray()
        try {
            encryptedDataGenerator.open(output, bytes.size.toLong()).use { outputStream -> outputStream.write(bytes) }
        } catch (e: Exception) {
            throw IOException(e.message)
        }
        output.close()
    }


    @Throws(IOException::class)
    fun inputStreamToByteArray(inputStream: InputStream): ByteArray? {
        val buffer = ByteArrayOutputStream()
        var readedByte: Int
        val data = ByteArray(1024)
        while (inputStream.read(data, 0, data.size).also { readedByte = it } != -1) {
            buffer.write(data, 0, readedByte)
        }
        buffer.flush()
        return buffer.toByteArray()
    }


    @Throws(IOException::class, PGPException::class)
    fun verifySignature(
        fileName: String,
        b: ByteArray,
        keyIn: InputStream
    ) {
        var pgpFact: PGPObjectFactory = BcPGPObjectFactory(b)
        val pgpSignatureList: PGPSignatureList
        val pgpObject = pgpFact.nextObject()
        if (pgpObject is PGPCompressedData) {
            pgpFact = BcPGPObjectFactory(pgpObject.dataStream)
            pgpSignatureList = pgpFact.nextObject() as PGPSignatureList
        } else {
            pgpSignatureList = pgpObject as PGPSignatureList
        }
        val pgpPubRingCollection: PGPPublicKeyRingCollection =
            BcPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn))
        var bufferedInputStream: BufferedInputStream
        var streamByte: Int
        val pgpSignature = pgpSignatureList[0]
        val key = pgpPubRingCollection.getPublicKey(pgpSignature.keyID)
        pgpSignature.init(JcaPGPContentVerifierBuilderProvider().setProvider(BouncyCastleProvider()), key)
        FileInputStream(fileName).use { fileInputStream -> //TODO refactor
            bufferedInputStream = BufferedInputStream(fileInputStream)
            while (bufferedInputStream.read().also { streamByte = it } >= 0) {
                pgpSignature.update(streamByte.toByte())
            }
        }
        if (pgpSignature.verify()) {
            System.err.println("signature verified.") // TODO add logger
        } else {
            System.err.println("signature verification failed.")
        }
    }


    @Throws(IOException::class, PGPException::class)
    fun readSecretKey(input: InputStream): PGPSecretKey {
        val pgpSec: PGPSecretKeyRingCollection = BcPGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(input)
        )
        val keyRingIter = pgpSec.keyRings
        while (keyRingIter.hasNext()) {
            val keyRing = keyRingIter.next() as PGPSecretKeyRing
            val keyIter = keyRing.secretKeys
            while (keyIter.hasNext()) {
                val key = keyIter.next() as PGPSecretKey
                if (key.isSigningKey) {
                    return key
                }
            }
        }
        throw IllegalArgumentException("Can't find signing key in key ring.")
    }


    @Throws(IOException::class, PGPException::class)
    fun createSignature(fileName: String, keyIn: InputStream, pass: CharArray, armor: Boolean): ByteArray? {
        val pgpSecKey = readSecretKey(keyIn)
        val pgpPrivKey = pgpSecKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider()).build(pass)
        )
        val pgpSignatureGenerator = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(
                pgpSecKey.publicKey.algorithm,
                HashAlgorithmTags.SHA1
            ).setProvider(BouncyCastleProvider())
        )
        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
        val byteOut = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteOut)
        val bcpgOutputStream = BCPGOutputStream(byteOut)
        FileInputStream(fileName).use { fileInputStream ->
            BufferedInputStream(fileInputStream).use { inputStream ->
                var input: Int
                while (inputStream.read().also { input = it } >= 0) {
                    pgpSignatureGenerator.update(input.toByte())
                }
            }
        }
        armoredOutputStream.endClearText()
        pgpSignatureGenerator.generate().encode(bcpgOutputStream)
        if (armor) {
            armoredOutputStream.close()
        }
        return byteOut.toByteArray()
    }
}