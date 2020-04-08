package com.erezbiox1.encryptedchat.server;

import com.erezbiox1.encryptedchat.encryption.HybridEncryption;
import com.erezbiox1.encryptedchat.encryption.TrustStore;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
@SuppressWarnings("WeakerAccess")
abstract public class SecureServer {

    private ServerSocket socket;
    private ServerThread thread;

    private TrustStore trustStore;
    private List<ClientSession> clientsList;
    private boolean running = false;

    public SecureServer(TrustStore trustStore, int port) throws IOException {
        this.trustStore = trustStore;
        this.socket = new ServerSocket(port);
        this.socket.setSoTimeout(0);
        this.thread = new ServerThread();

        clientsList = new ArrayList<>();
    }

    public void start(){
        running = true;
        thread.start();
    }

    public void stop(){
        running = false;
    }

    public List<ClientSession> getClientsList(){
        return clientsList;
    }

    class ServerThread extends Thread {
        @Override
        public void run() {
            while(running){
                try {

                    Socket client = SecureServer.this.socket.accept();
                    ServerEncryption encryption = new ServerEncryption(trustStore, client);
                    ClientSession session = new ClientSession(client, encryption);
                    SecureServer.this.clientsList.add(session);

                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void onOpen(ClientSession session){}
    public void onMessage(ClientSession session, String message){
        System.out.println(message);
    }
    public void onClose(ClientSession session){}

    public class ClientSession extends Thread {
        private Socket link;
        private ServerEncryption encryption;
        private DataInputStream in;
        private DataOutputStream out;

        private ClientSession(Socket link, ServerEncryption encryption) {
            this.link = link;
            this.encryption = encryption;
            start();
        }

        @Override
        public void run() {
            try {
                // Preform the handshake with the client
                encryption.handleHandshake();

                System.out.println(Base64.getEncoder().encodeToString(encryption.getAesKey().getEncoded()));

                // Set the encryption pipes
                in = new DataInputStream(link.getInputStream());
                out = new DataOutputStream(link.getOutputStream());

                SecureServer.this.onOpen(this);

                while (!link.isClosed()) {
                    String string = encryption.receive();
                    onMessage(this, string);
                }

            } catch (GeneralSecurityException e){
                e.printStackTrace();
            } catch (IOException e) {
                if(e.getMessage().contains("reset"))
                    disconnect();
                else
                    e.printStackTrace();
            }
        }

        public void sendMessage(String message) {
            try {
                encryption.send(message);
            } catch (IOException | GeneralSecurityException e) {
                e.printStackTrace();
            }
        }

        public void disconnect(){
            try {
                SecureServer.this.onClose(this);
                SecureServer.this.clientsList.remove(this);

                if(!link.isClosed())
                    link.close();

                in.close();
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
