package com.erezbiox1.encryptedchat.encryption;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class HybridEncryption {

    private TrustStore store;
    private String myAlias;

    private String otherAlias;
    private SecretKey aesKey;

    // The user's TrustStore, and the other user alias.
    public HybridEncryption(TrustStore store, String myAlias) {
        this.store = store;
        this.myAlias = myAlias;
    }

    public void handleClientHandshake(InputStream is, OutputStream os) throws IOException, GeneralSecurityException {
        DataInputStream in = new DataInputStream(is);
        DataOutputStream out = new DataOutputStream(os);

        // Send to the server the user's alias  ( unencrypted )
        out.writeUTF(myAlias);
        out.flush();

        // Send over my public key ( unencrypted )
        byte[] cert = store.getCertificate().getEncoded();
        out.writeInt(cert.length);
        out.flush();

        out.write(cert);
        out.flush();

        // Load the aes key ( encrypted with user public key )
        int aesKeyLength = in.readInt();
        if(aesKeyLength < 1)
            throw new IOException("Length is 0");

        byte[] aesKey = new byte[aesKeyLength];
        in.readFully(aesKey, 0, aesKeyLength);
        this.aesKey = new SecretKeySpec(decryptRSA(aesKey), "AES");

        // Get the server public key length ( encrypted with the AES key due to it's big size )
        int serverCertLength = in.readInt();
        if(serverCertLength < 1)
            throw new IOException("Length is 0");

        byte[] serverCert = new byte[serverCertLength];
        in.readFully(serverCert, 0, serverCertLength);
        store.setAliasCertificate("server", TrustStore.getCertificate(decryptAES(serverCert)));
        store.save();


    }

    public void handleServerHandshake(InputStream is, OutputStream os) throws IOException, GeneralSecurityException {
        System.out.println("Preforming handshake with client");
        DataInputStream in = new DataInputStream(is);
        DataOutputStream out = new DataOutputStream(os);

        // Get the client alias
        this.otherAlias = in.readUTF();

        // Get the client public key length
        int clientCertLength = in.readInt();
        if(clientCertLength < 1)
            throw new IOException("Length is 0");

        // Load the client's key, save it in the store.
        byte[] clientCert = new byte[clientCertLength];
        in.readFully(clientCert, 0, clientCertLength);
        store.setAliasCertificate(otherAlias, TrustStore.getCertificate(clientCert));
        store.save();

        // Generate a random AES key
        this.aesKey = generateAesKey();

        // Send over the random AES key, encrypted with the user public key
        byte[] aesKey = encryptRSA(this.aesKey.getEncoded());
        out.writeInt(aesKey.length);
        out.flush();

        out.write(aesKey);
        out.flush();

        // Send over the server public key, encrypted with the AES key due to it's big size
        byte[] cert = encryptAES(store.getCertificate().getEncoded());
        out.writeInt(cert.length);
        out.flush();

        out.write(cert);
        out.flush();
    }

    // Encrypt bytes using the class alias public key stored in the trust store
    private byte[] encryptRSA(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, store.getAliasCertificate(otherAlias).getPublicKey());
        return encryptCipher.doFinal(message);
    }

    // Decrypt bytes using the class private key stored in the trust store
    private byte[] decryptRSA(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, store.getPrivateKey());
        return encryptCipher.doFinal(message);
    }

    // Encrypt bytes using the class AES key
    private byte[] encryptAES(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return encryptCipher.doFinal(message);
    }

    // Decrypt bytes using the class AES key
    private byte[] decryptAES(byte[] message) throws GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.DECRYPT_MODE, aesKey);
        return encryptCipher.doFinal(message);
    }

    private SecretKey generateAesKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    // Get AES decryption stream using the random/received AES key.
    public CipherInputStream getDecryptionStream(InputStream in) throws GeneralSecurityException {
        Cipher decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE, aesKey);
        return new CipherInputStream(in, decryptCipher);
    }

    // Get the AES encryption stream using the random/received AES key.
    public CipherOutputStream getEncryptionStream(OutputStream out) throws  GeneralSecurityException {
        Cipher encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return new CipherOutputStream(out, encryptCipher);
    }

}
