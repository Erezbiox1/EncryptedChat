package com.erezbiox1.encryptedchat.server;

import com.erezbiox1.encryptedchat.encryption.ServerHybridEncryption;
import com.erezbiox1.encryptedchat.encryption.TrustStore;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class ServerEncryption extends ServerHybridEncryption {
    public ServerEncryption(TrustStore store, Socket socket) {
        super(store, "server", socket);
    }

    @Override
    public void handleHandshake() throws IOException, GeneralSecurityException {
        // Get the client alias
        this.otherAlias = in.readUTF();

        // Load the client's key, save it in the store.
        store.setAliasCertificate(otherAlias, TrustStore.getCertificate(loadBytes()));
        store.save();

        // Generate a random AES key
        this.aesKey = generateAesKey();

        // Send over the random AES key, encrypted with the user public key
        sendBytes(encryptRSA(this.aesKey.getEncoded()));

        // Send over the server public key, encrypted with the AES key due to it's big size
        sendBytes(encryptAES(store.getCertificate().getEncoded()));
    }

}
