package com.nbk;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class ImageController {

    private static final Logger logger = LoggerFactory.getLogger(ImageController.class);
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT_LOGGER");

    private static final long TOKEN_TTL_MS = 30_000L; // 30 seconds
    private static final int AES_KEY_SIZE = 16; // AES-128
    private static final int IV_SIZE = 16;

    // Token store: token -> {encryptedBytes, iv, aesKey, expiryMs}
    private final ConcurrentHashMap<String, TokenEntry> tokenStore = new ConcurrentHashMap<>();

    private final CloseableHttpClient httpClient;
    private static final String[] IP_HEADERS = {
            "X-Forwarded-For", "HTTP_X_FORWARDED_FOR", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "X-Real-IP", "x-real-ip"
    };

    @Value("${app.laserfiche.url}")
    private String laserficheUrl;

    @Value("${app.laserfiche.auth-header}")
    private String authHeader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // ─── Token Entry ────────────────────────────────────────────────────────────

    private static class TokenEntry {
        final byte[] encryptedBytes;
        final byte[] iv;
        final byte[] aesKey;
        final long expiryMs;

        TokenEntry(byte[] encryptedBytes, byte[] iv, byte[] aesKey, long expiryMs) {
            this.encryptedBytes = encryptedBytes;
            this.iv = iv;
            this.aesKey = aesKey;
            this.expiryMs = expiryMs;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expiryMs;
        }
    }

    // ─── Constructor ───────────────────────────────────────────────────────────

    public ImageController() {
        try {
            SSLContext sslContext = new SSLContextBuilder()
                    .loadTrustMaterial(null, (certificate, authType) -> true)
                    .build();

            this.httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();

        } catch (Exception e) {
            throw new RuntimeException("Failed to create HttpClient", e);
        }
    }

    // ─── Endpoint 1: Serve the secure canvas page ─────────────────────────────

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getImage(
            @RequestParam(name = "id") String encryptedToken,
            @RequestParam(name = "transactionId") String encTransactionId,
            @RequestParam(name = "userId") String encUserId,
            HttpServletRequest request) {

        String clientIp = getClientIp(request);
        String decryptedCif = null;
        String decryptedUserId = null;
        String decryptedTransId = null;
        boolean isSuccess = false;

        try {
            PrivateKey privateKey = KeyLoader.loadPrivateKey();

            // 1. Decrypt & Validate params
            decryptedCif = EncryptionOfTime.decryptAndValidate(encryptedToken, privateKey);
            decryptedUserId = EncryptionOfTime.decryptAndValidate(encUserId, privateKey);
            decryptedTransId = EncryptionOfTime.decryptAndValidate(encTransactionId, privateKey);

            // 2. Call upstream (Laserfiche)
            String jsonBody = "{\"CaseID\": \"8732\", \"RequestID\": \"\", \"DocumentType\": \"national id\"}";
            HttpGetWithEntity req = new HttpGetWithEntity(laserficheUrl);
            req.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));
            req.setHeader("Authorization", authHeader);
            req.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(req)) {
                int statusCode = response.getStatusLine().getStatusCode();
                if (statusCode != 200) {
                    throw new RuntimeException("Upstream failure: " + statusCode);
                }

                // 3. PDF → PNG bytes
                byte[] pdfBytes = extractAndDecodePdf(
                        EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
                byte[] imageBytes = convertPdfToImage(pdfBytes);

                // 4. Generate AES-128 key + IV, encrypt image
                SecureRandom rng = new SecureRandom();
                byte[] aesKey = new byte[AES_KEY_SIZE];
                byte[] iv = new byte[IV_SIZE];
                rng.nextBytes(aesKey);
                rng.nextBytes(iv);

                byte[] encrypted = encryptAes(imageBytes, aesKey, iv);

                // 5. Store one-time token (expires in 30 s)
                String otp = UUID.randomUUID().toString();
                tokenStore.put(otp, new TokenEntry(encrypted, iv, aesKey, System.currentTimeMillis() + TOKEN_TTL_MS));

                // 6. Build key bundle for JS: base64(iv + key) — JS will split them
                String ivB64 = Base64.getEncoder().encodeToString(iv);
                String keyB64 = Base64.getEncoder().encodeToString(aesKey);

                isSuccess = true;

                // Purge any stale tokens opportunistically
                purgeExpiredTokens();

                return ResponseEntity.ok()
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("X-Content-Type-Options", "nosniff")
                        .header("X-Frame-Options", "DENY")
                        .header("Content-Security-Policy",
                                "default-src 'self'; script-src 'unsafe-inline'; img-src 'none'; connect-src 'self'; style-src 'unsafe-inline';")
                        .body(buildSecureHtml(otp, ivB64, keyB64));
            }

        } catch (Exception ex) {
            logger.error("Error in getImage: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .body("<html><body>Error: " + escapeHtml(ex.getMessage()) + "</body></html>");

        } finally {
            auditLogger.info(
                    "{} | ip={} | user={} | transId={} | cif={} | status={}",
                    Instant.now(), clientIp,
                    decryptedUserId != null ? decryptedUserId : "UNAUTHORIZED",
                    decryptedTransId != null ? decryptedTransId : "UNKNOWN",
                    decryptedCif != null ? decryptedCif : "UNAUTHORIZED",
                    isSuccess ? "SUCCESS" : "FAILED");
        }
    }

    // ─── Endpoint 2: Serve AES-encrypted image bytes (one-time) ───────────────

    @GetMapping(value = "/api/image/data", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> getEncryptedImageData(
            @RequestParam(name = "token") String token) {

        TokenEntry entry = tokenStore.remove(token); // consume immediately — single use

        if (entry == null || entry.isExpired()) {
            logger.warn("Invalid or expired token requested: {}", token);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        // Prepend IV to the ciphertext so the client can split them
        byte[] payload = new byte[IV_SIZE + entry.encryptedBytes.length];
        System.arraycopy(entry.iv, 0, payload, 0, IV_SIZE);
        System.arraycopy(entry.encryptedBytes, 0, payload, IV_SIZE, entry.encryptedBytes.length);

        return ResponseEntity.ok()
                .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                .header("Pragma", "no-cache")
                .header("X-Content-Type-Options", "nosniff")
                .header("Content-Disposition", "inline")
                .body(payload);
    }

    // ─── AES-128-CBC encrypt ───────────────────────────────────────────────────

    private byte[] encryptAes(byte[] data, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    // ─── HTML builder ─────────────────────────────────────────────────────────

    private String buildSecureHtml(String otp, String ivB64, String keyB64) {
        return "<!DOCTYPE html>\n" +
                "<html lang=\"en\">\n" +
                "<head>\n" +
                "  <meta charset=\"UTF-8\">\n" +
                "  <meta http-equiv=\"Cache-Control\" content=\"no-store, no-cache, must-revalidate\">\n" +
                "  <meta http-equiv=\"Pragma\" content=\"no-cache\">\n" +
                "  <title>Document Viewer</title>\n" +
                "  <style>\n" +
                "    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n" +
                "    html, body {\n" +
                "      width: 100%; height: 100%;\n" +
                "      background: #111;\n" +
                "      display: flex;\n" +
                "      align-items: center;\n" +
                "      justify-content: center;\n" +
                "      overflow: auto;\n" +
                "      user-select: none;\n" +
                "      -webkit-user-select: none;\n" +
                "      -moz-user-select: none;\n" +
                "    }\n" +
                "    #c {\n" +
                "      max-width: 95vw;\n" +
                "      max-height: 95vh;\n" +
                "      display: block;\n" +
                "      box-shadow: 0 0 40px rgba(0,0,0,0.8);\n" +
                "      border-radius: 4px;\n" +
                "    }\n" +
                "    #overlay {\n" +
                "      position: fixed; inset: 0;\n" +
                "      z-index: 999;\n" +
                "      background: transparent;\n" +
                "      pointer-events: none;\n" +
                "    }\n" +
                "    #status {\n" +
                "      color: #aaa;\n" +
                "      font-family: sans-serif;\n" +
                "      font-size: 14px;\n" +
                "    }\n" +
                "    @media print { body { visibility: hidden !important; } }\n" +
                "  </style>\n" +
                "</head>\n" +
                "<body oncontextmenu=\"return false\" ondragstart=\"return false\" onselectstart=\"return false\">\n" +
                "  <div id=\"overlay\"></div>\n" +
                "  <canvas id=\"c\"></canvas>\n" +
                "  <p id=\"status\">Loading secure document…</p>\n" +
                "\n" +
                "  <script>\n" +
                "  (function() {\n" +
                // ── Security hardening ──────────────────────────────────────────────
                "    'use strict';\n" +
                "\n" +
                "    // Block key shortcuts\n" +
                "    document.addEventListener('keydown', function(e) {\n" +
                "      var blocked =\n" +
                "        e.key === 'F12' ||\n" +
                "        e.key === 'PrintScreen' ||\n" +
                "        (e.ctrlKey && ['s','p','u','a','c','x'].indexOf(e.key.toLowerCase()) !== -1) ||\n" +
                "        (e.ctrlKey && e.shiftKey && ['i','j','c'].indexOf(e.key.toLowerCase()) !== -1) ||\n" +
                "        (e.metaKey && ['s','p','u'].indexOf(e.key.toLowerCase()) !== -1);\n" +
                "      if (blocked) { e.preventDefault(); e.stopPropagation(); }\n" +
                "    }, true);\n" +
                "\n" +
                "    // Block right-click everywhere\n" +
                "    document.addEventListener('contextmenu', function(e) { e.preventDefault(); }, true);\n" +
                "\n" +
                "    // Aggressive Anti-DevTools heuristics\n" +
                "    var _w = window.outerWidth, _h = window.outerHeight;\n" +
                "    function destroyContent() {\n" +
                "      document.body.innerHTML = '<h1 style=\"color:red; text-align:center; margin-top:50px; font-family:sans-serif;\">Security Violation: Inspection Detected</h1>';\n"
                +
                "      if (window.stop) window.stop();\n" +
                "    }\n" +
                "\n" +
                "    // 1. Check for window resizing (docked devtools)\n" +
                "    setInterval(function() {\n" +
                "      if (Math.abs(window.outerWidth - _w) > 160 || Math.abs(window.outerHeight - _h) > 160) {\n" +
                "        destroyContent();\n" +
                "      }\n" +
                "    }, 500);\n" +
                "\n" +
                // ── Crypto constants injected by server ─────────────────────────────
                "    var OTP    = '" + escapeJs(otp) + "';\n" +
                "    var IV_B64 = '" + escapeJs(ivB64) + "';\n" +
                "    var KEY_B64= '" + escapeJs(keyB64) + "';\n" +
                "\n" +
                // ── Helpers ─────────────────────────────────────────────────────────
                "    function b64ToArr(b64) {\n" +
                "      var bin = atob(b64), arr = new Uint8Array(bin.length);\n" +
                "      for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);\n" +
                "      return arr;\n" +
                "    }\n" +
                "\n" +
                // ── Main: fetch → decrypt → paint ───────────────────────────────────
                "    async function loadImage() {\n" +
                "      var status = document.getElementById('status');\n" +
                "      try {\n" +
                "        var resp = await fetch('/api/image/data?token=' + encodeURIComponent(OTP), {\n" +
                "          credentials: 'same-origin',\n" +
                "          cache: 'no-store'\n" +
                "        });\n" +
                "        if (!resp.ok) throw new Error('Access denied (' + resp.status + ')');\n" +
                "\n" +
                "        var payload = new Uint8Array(await resp.arrayBuffer());\n" +
                "\n" +
                "        // Extract IV (first 16 bytes) and ciphertext (rest)\n" +
                "        var iv  = payload.slice(0, 16);\n" +
                "        var enc = payload.slice(16);\n" +
                "\n" +
                "        // Import AES-CBC key\n" +
                "        var rawKey = b64ToArr(KEY_B64);\n" +
                "        var cryptoKey = await crypto.subtle.importKey(\n" +
                "          'raw', rawKey, { name: 'AES-CBC' }, false, ['decrypt']\n" +
                "        );\n" +
                "\n" +
                "        // Decrypt\n" +
                "        var decrypted = await crypto.subtle.decrypt(\n" +
                "          { name: 'AES-CBC', iv: iv }, cryptoKey, enc\n" +
                "        );\n" +
                "\n" +
                "        // Wipe key references from memory (best-effort)\n" +
                "        rawKey.fill(0);\n" +
                "        KEY_B64 = null;\n" +
                "        IV_B64  = null;\n" +
                "        OTP     = null;\n" +
                "\n" +
                "        // Paint to canvas\n" +
                "        var blob = new Blob([decrypted], { type: 'image/png' });\n" +
                "        var bitmap = await createImageBitmap(blob);\n" +
                "        var canvas = document.getElementById('c');\n" +
                "        canvas.width  = bitmap.width;\n" +
                "        canvas.height = bitmap.height;\n" +
                "        var ctx = canvas.getContext('2d');\n" +
                "        ctx.drawImage(bitmap, 0, 0);\n" +
                "        bitmap.close();\n" +
                "\n" +
                "        // Remove status message\n" +
                "        status.remove();\n" +
                "\n" +
                "        // Prevent canvas right-click save\n" +
                "        canvas.addEventListener('contextmenu', function(e) { e.preventDefault(); }, true);\n" +
                "\n" +
                "        // Protect the pixel data — override toDataURL and toBlob\n" +
                "        canvas.toDataURL = function() { return ''; };\n" +
                "        canvas.toBlob    = function() {};\n" +
                "\n" +
                "      } catch (err) {\n" +
                "        status.textContent = 'Unable to load document: ' + err.message;\n" +
                "      }\n" +
                "    }\n" +
                "\n" +
                "    loadImage();\n" +
                "  })();\n" +
                "  </script>\n" +
                "</body>\n" +
                "</html>\n";
    }

    // ─── Helpers ───────────────────────────────────────────────────────────────

    private void purgeExpiredTokens() {
        tokenStore.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    private String escapeJs(String s) {
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "");
    }

    private String escapeHtml(String s) {
        if (s == null)
            return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private byte[] convertPdfToImage(byte[] data) throws Exception {
        try (PDDocument document = PDDocument.load(data)) {
            int pageCount = document.getNumberOfPages();
            PDFRenderer renderer = new PDFRenderer(document);

            BufferedImage[] images = new BufferedImage[pageCount];
            int totalWidth = 0;
            int maxHeight = 0;

            for (int i = 0; i < pageCount; i++) {
                images[i] = renderer.renderImageWithDPI(i, 150, ImageType.RGB);
                totalWidth += images[i].getWidth();
                maxHeight = Math.max(maxHeight, images[i].getHeight());
            }

            BufferedImage combined = new BufferedImage(totalWidth, maxHeight, BufferedImage.TYPE_INT_RGB);
            java.awt.Graphics2D g = combined.createGraphics();
            g.setBackground(java.awt.Color.BLACK);
            g.clearRect(0, 0, totalWidth, maxHeight);

            int currentX = 0;
            for (BufferedImage img : images) {
                g.drawImage(img, currentX, 0, null);
                currentX += img.getWidth();
            }
            g.dispose();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(combined, "png", baos);
            return baos.toByteArray();
        } catch (Exception e) {
            return data;
        }
    }

    private String getClientIp(HttpServletRequest request) {
        for (String header : IP_HEADERS) {
            String value = request.getHeader(header);
            if (value != null && !value.isEmpty() && !"unknown".equalsIgnoreCase(value)) {
                return value.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    private byte[] extractAndDecodePdf(String json) {
        try {
            JsonNode rootNode = objectMapper.readTree(json);
            return Base64.getDecoder().decode(rootNode.get("StreamBytes").asText());
        } catch (Exception e) {
            throw new RuntimeException("Decode Error");
        }
    }

    static class HttpGetWithEntity extends HttpEntityEnclosingRequestBase {
        public static final String METHOD_NAME = "GET";

        public HttpGetWithEntity(String uri) {
            setURI(URI.create(uri));
        }

        @Override
        public String getMethod() {
            return METHOD_NAME;
        }
    }
}