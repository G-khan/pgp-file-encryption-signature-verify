package securepgp

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPException
import securepgp.pgp.PgpHelper
import securepgp.pgp.RSAKeyPairGenerator
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.Security

class PGPProcessor {

    private val isArmored = false
    private val id = "gokhana"
    private val passwd = "hongkong"
    private val integrityCheck = true


    private val pubKeyFile = "./src/main/resources/sign-and-encrypt_pub.asc"
    private val privKeyFile = "./src/main/resources/sign-and-encrypt_priv.asc"

    private val plainTextFile =
        "./src/main/resources/sample_data.csv" //create a text file to be encripted, before run the tests

    private val cipherTextFile = "./cypher-sample.csv"
    private val decPlainTextFile = "./dec-sample.csv"
    private val signatureFile = "./signature.txt"


    @Throws(NoSuchProviderException::class, IOException::class, PGPException::class, NoSuchAlgorithmException::class)
    fun genKeyPair() {
        val rkpg = RSAKeyPairGenerator()
        Security.addProvider(BouncyCastleProvider())
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(1024)
        val kp = kpg.generateKeyPair()
        val secretOut = FileOutputStream(privKeyFile)
        val publicOut = FileOutputStream(pubKeyFile)
        rkpg.exportKeyPair(secretOut, publicOut, kp.public, kp.private, id, passwd.toCharArray(), isArmored)
        secretOut.close()
        publicOut.close()
    }

    @Throws(NoSuchProviderException::class, IOException::class, PGPException::class)
    fun encrypt() {
        val pubKeyIs = FileInputStream(pubKeyFile)
        val cipheredFileIs = FileOutputStream(cipherTextFile)
        PgpHelper.encryptFile(
            cipheredFileIs,
            plainTextFile,
            PgpHelper.readPublicKey(pubKeyIs),
            isArmored,
            integrityCheck
        )
        cipheredFileIs.close()
        pubKeyIs.close()
    }

    @Throws(Exception::class)
    fun decrypt() {
        val cipheredFileIs = FileInputStream(cipherTextFile)
        val privKeyIn = FileInputStream(privKeyFile)
        val plainTextFileIs = FileOutputStream(decPlainTextFile)
        PgpHelper.decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray())
        cipheredFileIs.close()
        plainTextFileIs.close()
        privKeyIn.close()
    }

    @Throws(Exception::class)
    fun signAndVerify() {
        val privKeyIn = FileInputStream(privKeyFile)
        val pubKeyIs = FileInputStream(pubKeyFile)
        val signatureOut = FileOutputStream(signatureFile)
        val sig: ByteArray =
            PgpHelper.createSignature(plainTextFile, privKeyIn, passwd.toCharArray(), true)
        signatureOut.write(sig)
        signatureOut.close()
        val sigByte = Files.readAllBytes(Paths.get(signatureFile))
        PgpHelper.verifySignature(plainTextFile, sigByte, pubKeyIs)
    }

}