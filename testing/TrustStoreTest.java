import static org.junit.jupiter.api.Assertions.*;

import com.erezbiox1.encryptedchat.encryption.TrustStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * Created by Erezbiox1 on 08/04/2020.
 * (C) 2020 Erez Rotem All Rights Reserved.
 */
class TrustStoreTest {

    @SuppressWarnings("WeakerAccess")
    @TempDir
    public Path tempDir;

    @Test
    void checkTrustStoreLoading() throws GeneralSecurityException, IOException {
        // Creating a new TrustStore
        TrustStore trustStore = initStore("test");

        // Getting it's keys
        PublicKey publicKey = trustStore.getPublicKey();
        PrivateKey privateKey = trustStore.getPrivateKey();

        // Saving it to the file system
        trustStore.save();

        // Loading it from the file system
        trustStore = initStore("test");

        // Comparing the keys before and after the load. ( to check if they were loaded or generated )
        assertArrayEquals(trustStore.getPrivateKey().getEncoded(), privateKey.getEncoded());
        assertArrayEquals(trustStore.getPublicKey().getEncoded(), publicKey.getEncoded());
    }

    @Test
    void checkKeyPairIntegrity() throws GeneralSecurityException, IOException {
        TrustStore trustStore = initStore("test");

        // Getting the public and private keys length..
        int privateKeyLength = trustStore.getPrivateKey().getEncoded().length;
        int publicKeyLength = trustStore.getPublicKey().getEncoded().length;

        // Asserting their length..
        assertTrue(privateKeyLength > 1210, "Private key length must be at least a 1210. Was: " + privateKeyLength);
        assertTrue(publicKeyLength > 290, "Public key length must be at least a 290. Was: " + publicKeyLength);
    }

    @Test
    void checkCertificateSavingAndLoading() throws GeneralSecurityException, IOException {
        // Creating 2 stores. ( one is the user's and one is another person for example )
        TrustStore trustStore = initStore("test");
        TrustStore otherStore = initStore("other");

        // Getting the other's encoded certificate, recreating it then saving it to the user's certificate
        // ( To simulate a real world scenario.
        byte[] otherCertificate = otherStore.getCertificate().getEncoded();
        Certificate cert = TrustStore.getCertificate(otherCertificate);
        trustStore.setAliasCertificate("other", cert);

        // Saving the user's keystore
        trustStore.save();

        // Reloading the user's Trust Store.
        trustStore = initStore("test");

        // Comparing the generated key vs the loaded key
        assertArrayEquals(trustStore.getAliasCertificate("other").getEncoded(), otherCertificate);
    }

    private TrustStore initStore(String name) throws GeneralSecurityException, IOException {
        return TrustStore.getInstance(tempDir.resolve(name + ".jks").toAbsolutePath().toString(), "password");
    }

}
