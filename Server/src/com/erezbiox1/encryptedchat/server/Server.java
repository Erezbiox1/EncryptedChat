package com.erezbiox1.encryptedchat.server;

import com.erezbiox1.encryptedchat.encryption.TrustStore;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.GeneralSecurityException;
import java.util.Scanner;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class Server extends Thread {
    public static void main(String[] args) throws IOException, GeneralSecurityException {

        TrustStore store = TrustStore.getInstance("server.jks", "password");
        SecureServer server = new SecureServer(store, 8907) {
            @Override
            public void onOpen(ClientSession session) {
                session.sendMessage("Welcome!");
                System.out.println("New client connected!");
            }

            @Override
            public void onMessage(ClientSession session, String message) {
                System.out.println(message);
            }

            @Override
            public void onClose(ClientSession session) {
                System.out.println("A client has left the server!");
            }
        };

        System.out.println("Starting server...");
        server.start();

        Scanner in = new Scanner(System.in);
        while(true){
            String line = in.nextLine();
            if(line.equals("/exit"))
                break;

            server.getClientsList().forEach(client -> client.sendMessage(line));
        }
    }

}
