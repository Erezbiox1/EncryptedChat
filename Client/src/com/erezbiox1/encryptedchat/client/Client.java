package com.erezbiox1.encryptedchat.client;

import com.erezbiox1.encryptedchat.encryption.HybridEncryption;
import com.erezbiox1.encryptedchat.encryption.TrustStore;
import com.sun.xml.internal.ws.addressing.WsaActionUtil;

import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Scanner;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
public class Client {
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        TrustStore store = TrustStore.getInstance("client.jks", "password");

        SecureClient client = new SecureClient(store, "erez", "localhost", 8907) {
            @Override
            public void onMessage(String message) {
                System.out.println(message);
            }
        };

        System.out.println("Connected successfully!");
        Scanner in = new Scanner(System.in);
        while(true){
            String line = in.nextLine();
            if(line.equals("/exit"))
                break;

            client.sendMessage(line);
        }

    }
}
