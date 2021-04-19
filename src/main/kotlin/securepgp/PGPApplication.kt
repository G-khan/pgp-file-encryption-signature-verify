package securepgp

class PGPApplication


fun main(args: Array<String>) {
    val test = PGPProcessor()
    test.genKeyPair()
    println("keypair generated.")
    test.encrypt()
    println("encryption completed.")
    test.signAndVerify()
    println("signed And Verified.")
    test.decrypt()
    println("decryption completed for encrypted file.")

}


