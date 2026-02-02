package com.nbk;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;

public class EncryptionOfTimeTest {
	public static void generateMockApiRequest() throws Exception {
	    // 1. Setup Keys (In production, load these via KeyLoader)
	    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	    kpg.initialize(2048);
	    KeyPair pair = kpg.generateKeyPair();
	    
	    // 2. Mock Data
	    String mockCif = "123456789"; // The identity being wrapped
	    String mockUserId = "staff_user_01"; // The person requesting the view
	    String mockTransId = "TXN-" + System.currentTimeMillis(); // Unique Transaction ID
	    
	    // 3. Generate the Secure Token (The "id" parameter)
	    String encryptedToken = EncryptionOfTime.generateEncryptedToken(mockCif, KeyLoader.loadPublicKey());
	    String encryptedMockUserId =  EncryptionOfTime.generateEncryptedToken(mockUserId, KeyLoader.loadPublicKey());
	    String encryptedMockTransId =EncryptionOfTime.generateEncryptedToken(mockTransId, KeyLoader.loadPublicKey());
	    // 4. Construct the Mock API URL
	    String mockUrl = String.format(
	        "http://localhost:9900?id=%s&transactionId=%s&userId=%s",
	        encryptedToken,
	        encryptedMockTransId,
	        encryptedMockUserId
	    );

	    System.out.println("--- MOCK API REQUEST URL ---");
	    System.out.println(mockUrl);
	}
    /**
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        // 1. SETUP: Generate Keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();

        System.out.println("============================================");
        System.out.println("SECURITY TEST SUITE: SIGNATURE WEBAPP");
        System.out.println("============================================\n");

        // TEST 1: SUCCESS CASE (The Happy Path)
        runTest("SUCCESS CASE", "888999", 0, priv, pub);

        // TEST 2: EXPIRED TOKEN (User waited > 5 minutes)
        // Simulate a token created 10 minutes ago
        runTest("FAILURE: EXPIRED TOKEN", "888999", -10 * 60 * 1000, priv, pub);

        // TEST 3: FUTURE TOKEN (Server Clocks Out of Sync)
        // Simulate a token from 10 minutes in the future
        runTest("FAILURE: FUTURE TIMESTAMP", "888999", 10 * 60 * 1000, priv, pub);

        // TEST 4: TAMPERED DATA (Malicious user changed the Base64)
        runTamperTest("FAILURE: TAMPERED BASE64", priv);

        // TEST 5: WRONG FORMAT (Decrypted but missing the '|')
        runFormatTest("FAILURE: INVALID PAYLOAD FORMAT", priv, pub);
     // CASE A: Exactly 4 minutes ago (Should PASS)
        // Within the 5-minute window
        runTest("TIME: 4 MINS AGO", "USER123", -4 * 60 * 1000, priv, pub);

        // CASE B: Exactly 6 minutes ago (Should FAIL)
        // Outside the 5-minute window
        runTest("TIME: 6 MINS AGO", "USER123", -6 * 60 * 1000, priv, pub);

        // CASE C: Exactly 2 minutes in the future (Should PASS)
        // Within the 3-minute Clock Skew buffer
        runTest("TIME: 2 MINS FUTURE", "USER123", 2 * 60 * 1000, priv, pub);

        // CASE D: Exactly 4 minutes in the future (Should FAIL)
        // Outside the 3-minute Clock Skew buffer
        runTest("TIME: 4 MINS FUTURE", "USER123", 4 * 60 * 1000, priv, pub);
     // CASE A: 7 minutes ago (Should still PASS because 7 < 8)
        runTest("TIME: 7 MINS AGO", "USER123", -7 * 60 * 1000, priv, pub);

        // CASE B: 9 minutes ago (Should FAIL because 9 > 8)
        // This is the one that proves your security works!
        runTest("TIME: 9 MINS AGO", "USER123", -9 * 60 * 1000, priv, pub);

        // CASE C: 5 minutes in the future (Should FAIL because 5 > 3)
        runTest("TIME: 5 MINS FUTURE", "USER123", 5 * 60 * 1000, priv, pub);
        System.out.println("============================================");
        System.out.println("TESTING COMPLETE");
        generateMockApiRequest();
    }

    /**
     * Helper to run time-based tests
     */
    private static void runTest(String testName, String userId, long timeOffsetMs, PrivateKey priv, PublicKey pub) {
        System.out.print("[" + testName + "]: ");
        try {
            // Create custom timestamp
            long customTime = System.currentTimeMillis() + timeOffsetMs;
            String payload = userId + "|" + customTime;
            
            // Encrypt
            String token = encryptRaw(payload, pub);
            
            // Validate
            String result = EncryptionOfTime.decryptAndValidate(token, priv);
            System.out.println("PASSED (User: " + result + ")");
        } catch (SecurityException e) {
            System.out.println("CAUGHT EXPECTED ERROR: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("UNEXPECTED SYSTEM ERROR: " + e.getMessage());
        }
    }

    private static void runTamperTest(String testName, PrivateKey priv) {
        System.out.print("[" + testName + "]: ");
        try {
            EncryptionOfTime.decryptAndValidate("NotAValidToken123", priv);
        } catch (SecurityException e) {
            System.out.println("CAUGHT EXPECTED ERROR: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("FAILED");
        }
    }

    private static void runFormatTest(String testName, PrivateKey priv, PublicKey pub) {
        System.out.print("[" + testName + "]: ");
        try {
            // Payload without the "|" separator
            String badToken = encryptRaw("BrokenPayloadNoSeparator", pub);
            EncryptionOfTime.decryptAndValidate(badToken, priv);
        } catch (SecurityException e) {
            System.out.println("CAUGHT EXPECTED ERROR: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("FAILED");
        }
    }

    // Helper to simulate T24 encryption
    private static String encryptRaw(String data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encrypted);
    }
}