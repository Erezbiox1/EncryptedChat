package com.erezbiox1.encryptedchat.encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
abstract public class HybridEncryption {

    protected TrustStore store;
    protected String myAlias;

    protected String otherAlias;
    protected SecretKey aesKey;

    protected DataInputStream in;
    protected DataOutputStream out;

    // The user's TrustStore, and the other user alias.
    public HybridEncryption(TrustStore store, String myAlias) {
        this.store = store;
        this.myAlias = myAlias;
    }

    public SecretKey getAesKey() {
        return aesKey;
    }

    public abstract void handleHandshake() throws IOException, GeneralSecurityException;

    // Encrypt bytes using the class alias public key stored in the trust store
    protected byte[] encryptRSA(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, store.getAliasCertificate(otherAlias).getPublicKey());
        return encryptCipher.doFinal(message);
    }

    // Decrypt bytes using the class private key stored in the trust store
    protected byte[] decryptRSA(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, store.getPrivateKey());
        return encryptCipher.doFinal(message);
    }

    // Encrypt bytes using the class AES key
    protected byte[] encryptAES(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return encryptCipher.doFinal(message);
    }

    // Decrypt bytes using the class AES key
    protected byte[] decryptAES(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.DECRYPT_MODE, aesKey);
        return encryptCipher.doFinal(message);
    }

    // Generate a random 256 AES key.
    protected static SecretKey generateAesKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }



    // Unused

//    // Get AES decryption stream using the random/received AES key.
//    @Deprecated
//    public CipherInputStream getDecryptionStream(InputStream in) throws GeneralSecurityException {
//        Cipher decryptCipher = Cipher.getInstance("AES");
//        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey);
//        return new CipherInputStream(in, decryptCipher);
//    }
//
//    // Get the AES encryption stream using the random/received AES key.
//    @Deprecated
//    public CipherOutputStream getEncryptionStream(OutputStream out) throws GeneralSecurityException {
//        Cipher encryptCipher = Cipher.getInstance("AES");
//        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
//        return new CipherOutputStream(out, encryptCipher);
//    }

}
