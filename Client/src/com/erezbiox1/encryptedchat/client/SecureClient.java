package com.erezbiox1.encryptedchat.client;

import com.erezbiox1.encryptedchat.encryption.TrustStore;

import java.io.*;
import java.net.ConnectException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
@SuppressWarnings("WeakerAccess")
public abstract class SecureClient extends Thread {

    private Socket socket;
    private ClientEncryption transport;

    private boolean running = true;

    public SecureClient(TrustStore store, String alias, String serverName, int port) throws IOException {
        this.socket = new Socket(serverName, port);
        this.transport = new ClientEncryption(store, alias, this.socket);

        start();
    }

    @Override
    public void run() {
        try {
            transport.handleHandshake();
            System.out.println(Base64.getEncoder().encodeToString(transport.getAesKey().getEncoded()));

            while(running && !socket.isClosed()){
                String string = transport.receive();
                onMessage(string);
            }

        }catch (EOFException e) {
            System.err.println("You were disconnected from the server.");
            disconnect();
        }catch (ConnectException e) {
            System.err.println("Cannot connect to the server.");
            disconnect();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public abstract void onMessage(String message);

    public void sendMessage(String message){
        try {
            transport.send(message);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    protected void disconnect(){
        try{
            transport.close();
            running = false;
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
