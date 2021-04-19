
# pgp-file-encryption-signature-verfiy
PGP file encryption &amp; decryption and sigature &amp; verify via bouncycastle with Kotlin


**Step 1: Running the PGP Application**

Open the pgp-file-encryption-signature-verify path then,
Type the following commands in your terminal to run the banking service

    ./gradlew clean build
    ./gradlew run


Logs after run the application:


    $ ./gradlew run
    
    > Task :run
    keypair generated.
    encryption completed.
    signature verified.
    signed And Verified.
    decryption completed for encrypted file.

Inspired by examples of bouncycastle.openPGP -> [github opengpg examples](https://github.com/bcgit/bc-java/tree/master/pg/src/main/java/org/bouncycastle/openpgp/examples) and [youngclown's example](https://github.com/youngclown/JavaPGPSample)