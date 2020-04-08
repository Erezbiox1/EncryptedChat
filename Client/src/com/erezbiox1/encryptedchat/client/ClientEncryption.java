package com.erezbiox1.encryptedchat.client;

import com.erezbiox1.encryptedchat.encryption.ServerHybridEncryption;
import com.erezbiox1.encryptedchat.encryption.TrustStore;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class ClientEncryption extends ServerHybridEncryption {

    public ClientEncryption(TrustStore store, String myAlias, Socket socket) {
        super(store, myAlias, socket);
    }

    @Override
    public void handleHandshake() throws IOException, GeneralSecurityException {
        // Send to the server the user's alias  ( unencrypted )
        out.writeUTF(myAlias);
        out.flush();

        // Send over my public key ( unencrypted )
        sendBytes(store.getCertificate().getEncoded());

        // Load the aes key ( encrypted with user public key )
        this.aesKey = new SecretKeySpec(decryptRSA(loadBytes()), "AES");

        // Get the server public key length ( encrypted with the AES key due to it's big size )
        store.setAliasCertificate("server", TrustStore.getCertificate(decryptAES(loadBytes())));
        store.save();
    }
}
