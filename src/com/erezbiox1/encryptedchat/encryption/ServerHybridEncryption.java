package com.erezbiox1.encryptedchat.encryption;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Created by Erezbiox1 on 09/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public abstract class ServerHybridEncryption extends HybridEncryption {

    protected DataInputStream in;
    protected DataOutputStream out;

    public ServerHybridEncryption(TrustStore store, String myAlias, Socket socket) {
        super(store, myAlias);
        try {
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new DataOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String receive() throws GeneralSecurityException, IOException {
        byte[] message = loadBytes();
        byte[] decrypted = decryptAES(message);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    public void send(String message) throws GeneralSecurityException, IOException {
        byte[] array = message.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encryptAES(array);
        sendBytes(encrypted);
    }

    public void close() throws IOException {
        in.close();
        out.close();
    }

    protected void sendBytes(byte[] array) throws IOException {
        out.writeInt(array.length);
        out.flush();

        out.write(array);
        out.flush();
    }

    protected byte[] loadBytes() throws IOException {
        int length = in.readInt();
        if(length < 1)
            throw new IOException("Length is 0");

        byte[] data = new byte[length];
        in.readFully(data, 0, length);

        return data;
    }

}
