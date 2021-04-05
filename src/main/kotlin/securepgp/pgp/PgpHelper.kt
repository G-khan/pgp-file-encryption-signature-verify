package securepgp.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
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
        var out = out
        this.getProvider()
        if (armor) {
            out = ArmoredOutputStream(out)
        }
        val bOut = ByteArrayOutputStream()
        val comData = PGPCompressedDataGenerator(
            CompressionAlgorithmTags.ZIP
        )
        PGPUtil.writeFileToLiteralData(
            comData.open(bOut),
            PGPLiteralData.BINARY, File(fileName)
        )
        comData.close()
        val c = JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5).setWithIntegrityPacket(withIntegrityCheck)
            .setSecureRandom(
                SecureRandom()
            ).setProvider("BC")
        val cPk = PGPEncryptedDataGenerator(c)
        val d = JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(BouncyCastleProvider()).setSecureRandom(
            SecureRandom()
        )
        cPk.addMethod(d)
        val bytes = bOut.toByteArray()
        try {
            cPk.open(out, bytes.size.toLong()).use { cOut -> cOut.write(bytes) }
        } catch (e: Exception) {
            throw IOException(e.message)
        }
        out.close()
    }


}