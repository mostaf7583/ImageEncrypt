package com.nbk;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Utility for the Secure Identity Transfer Project.
 * Enhances service time by allowing instant user verification
 * and provides a unified user experience across banking platforms.
 */
public class EncryptionOfTime {

    // CONFIGURATION
    // 5-minute window as per documentation to balance security and UX
    private static final long VALIDITY_DURATION_MS = 5 * 60 * 1000; 
    // Buffer for clock drift between T24 and Web App servers
    private static final long CLOCK_SKEW_BUFFER_MS = 3 * 60 * 1000; 
    
    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding"; 

    /**
     * FUNCTION 1: ENCRYPTION (T24 Side)
     * Wraps user identity in a digital vault for secure transfer.
     * * @param userId The unique user identifier (e.g., "100205")
     * @param publicKey The Public Key for encryption
     * @return URL-Safe Base64 String
     */
    public static String generateEncryptedToken(String userId, PublicKey publicKey) throws Exception {
        long t24Time = System.currentTimeMillis();

        // Pack the data: "USER_ID|TIMESTAMP"
        String payload = userId + "|" + t24Time;

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));

        // URL-Safe Base64 ensures the token doesn't break browser URLs
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encryptedBytes);
    }

    /**
     * FUNCTION 2: DECRYPTION & VALIDATION (Web App Side)
     * Validates the "Digital Bridge" and ensures the link is fresh.
     * * @param token The encrypted data parameter from the URL
     * @param privateKey The Private Key held only by the destination app
     * @return The userId if valid
     * @throws SecurityException if expired or tampering is detected
     */
    public static String decryptAndValidate(String token, PrivateKey privateKey) throws Exception {
        try {
            byte[] cipherBytes = Base64.getUrlDecoder().decode(token);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(cipherBytes);
            
            String decryptedPayload = new String(decryptedBytes, StandardCharsets.UTF_8);

            String[] parts = decryptedPayload.split("\\|", 2);
            if (parts.length != 2) {
                throw new SecurityException("Security Alert: Unauthorized transfer format.");
            }

            String userId = parts[0];
            long tokenCreationTime = Long.parseLong(parts[1]);
            long serverCurrentTime = System.currentTimeMillis();
            long difference = serverCurrentTime - tokenCreationTime;

            // Math: 5 mins + 3 mins buffer = 8 mins total allowed age
            if (difference > (VALIDITY_DURATION_MS + CLOCK_SKEW_BUFFER_MS)) {
                throw new SecurityException("Security Alert: The transfer link has expired.");
            }

            if (difference < -CLOCK_SKEW_BUFFER_MS) {
                throw new SecurityException("Security Alert: Invalid link timestamp.");
            }

            return userId;

        } catch (SecurityException e) {
            // IMPORTANT: Catch our specific security messages first!
            throw e; 
        } catch (javax.crypto.BadPaddingException e) {
            throw new SecurityException("Security Alert: Unauthorized or corrupted identity transfer.");
        } catch (Exception e) {
            // Only use this for unexpected system crashes
            throw new SecurityException("Security Alert: Internal validation failure.");
        }
    }

    public static void main(String[] args) throws Exception {
        // Simulation of key pair (Keys should be stored securely in production)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        
        String testUserId = "888999";

        System.out.println("--- Initiating Secure Handshake (T24) ---");
        String urlToken = generateEncryptedToken(testUserId, pair.getPublic());
        System.out.println("Secure Token: " + urlToken);

        System.out.println("\n--- Validating Bridge (Web App) ---");
        try {
            String extractedUser = decryptAndValidate(urlToken, pair.getPrivate());
            System.out.println("SUCCESS: Unified User Experience active for User: " + extractedUser);
            System.out.println("Service time enhanced: Manual login bypassed.");
        } catch (SecurityException e) {
            System.err.println("FAILED: " + e.getMessage());
        }
    }
}