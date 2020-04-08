package com.erezbiox1.encryptedchat.encryption;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class TrustStore {

    private static final String myKey = "__myKey__";

    private KeyStore keyStore;
    private String fileName;
    private String password;

    private Certificate certificate;
    private PrivateKey privateKey;

    private TrustStore(KeyStore keyStore, String fileName, String password, PrivateKeyEntry entry) {
        this.keyStore = keyStore;
        this.fileName = fileName;
        this.password = password;
        this.certificate = entry.getCertificate();
        this.privateKey = entry.getPrivateKey();
    }

    // Get the public key of an alias.
    public Certificate getAliasCertificate(String alias) throws KeyStoreException {
        return keyStore.getCertificate(alias);
    }

    // Set the public key of an alias.
    public void setAliasCertificate(String alias, Certificate certificate) throws KeyStoreException {
        keyStore.setCertificateEntry(alias, certificate);
    }

    // Get your own public key.
    public PublicKey getPublicKey(){
        return certificate.getPublicKey();
    }

    // Get your own certificate.
    public Certificate getCertificate(){
        return certificate;
    }

    // Get your own private key.
    public PrivateKey getPrivateKey(){
        return privateKey;
    }

    // Save the modifications made to the keystore to the keystore file.
    public void save() throws GeneralSecurityException, IOException {
        FileOutputStream out = new FileOutputStream(fileName);
        keyStore.store(out, password.toCharArray());
        out.close();
    }

    public static TrustStore getInstance(String fileName, String password) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("JKS");

        // Try loading the keystore file, if there isn't, create one
        try(InputStream in = Files.newInputStream(Paths.get(fileName))){
            ks.load(in, password.toCharArray());
        } catch (IOException e){
            ks.load(null, password.toCharArray());
        }

        // If the keystore contains the personal alias then get it otherwise generate it.
        PrivateKeyEntry entry = ks.containsAlias(myKey) ? getKeypairFromKeystore(ks, password) : generateKeyPair(ks, password);

        // Return the trust store instance
        return new TrustStore(ks, fileName, password, entry);
    }

    // Load keypair from the keystore
    private static PrivateKeyEntry getKeypairFromKeystore(KeyStore keyStore, String password) throws GeneralSecurityException {
        return (PrivateKeyEntry) keyStore.getEntry(myKey, new PasswordProtection(password.toCharArray()));
    }

    // Generate a key pair, save it to the keyStore protected with password.
    private static PrivateKeyEntry generateKeyPair(KeyStore keyStore, String password) throws GeneralSecurityException, IOException {
        CertAndKeyGen certGen = new CertAndKeyGen("RSA", "SHA256WithRSA");
        certGen.generate(2048);

        long validSecs = (long) 365 * 24 * 60 * 60;
        X509Certificate cert = certGen.getSelfCertificate(new X500Name("CN=EncryptedChat"), validSecs);

        PrivateKeyEntry entry = new PrivateKeyEntry(certGen.getPrivateKey(), new X509Certificate[] { cert });
        PasswordProtection protection = new PasswordProtection(password.toCharArray());

        keyStore.setEntry(myKey, entry, protection);

        return entry;
    }

    // Get certificate from a byte array
    public static Certificate getCertificate(byte[] certificate) throws CertificateException {
        return CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certificate));
    }

}
