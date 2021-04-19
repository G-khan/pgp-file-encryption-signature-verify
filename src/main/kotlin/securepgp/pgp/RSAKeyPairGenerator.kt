package securepgp.pgp

import org.bouncycastle.bcpg.*
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder
import java.io.IOException
import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.util.*

class RSAKeyPairGenerator {

    @Throws(IOException::class, PGPException::class)
    fun exportKeyPair(
        secretOut: OutputStream,
        publicOut: OutputStream,
        publicKey: PublicKey?,
        privateKey: PrivateKey,
        identity: String?,
        passPhrase: CharArray?,
        armor: Boolean
    ) {
        var secretOut = secretOut
        var publicOut = publicOut
        if (armor) {
            secretOut = ArmoredOutputStream(secretOut)
        }
        val pgpPublicKey = JcaPGPKeyConverter().getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, publicKey, Date())
        val rsaPrivateCrtKey = privateKey as RSAPrivateCrtKey
        val rsaSecretBCPGKey = RSASecretBCPGKey(rsaPrivateCrtKey.privateExponent, rsaPrivateCrtKey.primeP, rsaPrivateCrtKey.primeQ)
        val pgpPrivateKey = PGPPrivateKey(pgpPublicKey.keyID, pgpPublicKey.publicKeyPacket, rsaSecretBCPGKey)
        val sha1Calc = JcaPGPDigestCalculatorProviderBuilder().build()[HashAlgorithmTags.SHA1]
        val keyPair = PGPKeyPair(pgpPublicKey, pgpPrivateKey)
        val secretKey = PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION,
            keyPair,
            identity,
            sha1Calc,
            null,
            null,
            JcaPGPContentSignerBuilder(keyPair.publicKey.algorithm, HashAlgorithmTags.SHA1),
            JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.CAST5, sha1Calc).setProvider("BC")
                .build(passPhrase)
        )
        secretKey.encode(secretOut)
        secretOut.close()
        if (armor) {
            publicOut = ArmoredOutputStream(publicOut)
        }
        val key = secretKey.publicKey
        key.encode(publicOut)
        publicOut.close()
    }

}