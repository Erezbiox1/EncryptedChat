package com.erezbiox1.encryptedchat;

import com.erezbiox1.encryptedchat.encryption.TrustStore;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class Main {
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        TrustStore store = TrustStore.getInstance("keystore.jks", "123456");

        String publicKey = Base64.getEncoder().encodeToString(store.getPublicKey().getEncoded());
        String privateKey = Base64.getEncoder().encodeToString(store.getPrivateKey().getEncoded());

        System.out.println("publicKey = " + publicKey);
        System.out.println("privateKey = " + privateKey);

        store.save();

    }
}
