package com.nbk;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Base64;

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

    // Fixed return type to String for HTML output
    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getImage(
            @RequestParam(name = "id") String encryptedToken,
            @RequestParam(name = "transactionId") String encTransactionId,
            @RequestParam(name = "userId") String encUserId,
            HttpServletRequest request
    ) {
        String clientIp = getClientIp(request);
        String decryptedCif = null;
        String decryptedUserId = null;
        String decryptedTransId = null;
        boolean isSuccess = false;

        try {
            PrivateKey privateKey = KeyLoader.loadPrivateKey(); 

            // 1. Decrypt and Validate
            decryptedCif = EncryptionOfTime.decryptAndValidate(encryptedToken, privateKey);
            decryptedUserId = EncryptionOfTime.decryptAndValidate(encUserId, privateKey);
            decryptedTransId = EncryptionOfTime.decryptAndValidate(encTransactionId, privateKey);

            // 2. Upstream Request
            String jsonBody = "{\"CaseID\": \"8732\", \"RequestID\": \"\", \"DocumentType\": \"national id\"}";

            HttpGetWithEntity requestHttp = new HttpGetWithEntity(laserficheUrl);
            requestHttp.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));
            requestHttp.setHeader("Authorization", authHeader);
            requestHttp.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(requestHttp)) {
                int statusCode = response.getStatusLine().getStatusCode();
                
                if (statusCode != 200) {
                    return ResponseEntity.status(statusCode).body("Upstream Failure");
                }

                // 3. Convert and Wrap
                byte[] pdfBytes = extractAndDecodePdf(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
                byte[] imageBytes = convertPdfToImage(pdfBytes);
                String base64Image = Base64.getEncoder().encodeToString(imageBytes);

                isSuccess = true;
                String htmlResponse = secureHtml(base64Image);
                
                return ResponseEntity.ok()
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .body(htmlResponse);
            }

        } catch (SecurityException se) {
            logger.warn("Security Alert: {} | IP: {}", se.getMessage(), clientIp);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        } catch (Exception e) {
            logger.error("Internal Error", e);
            return ResponseEntity.internalServerError().body("Processing Error");
        } finally {
            auditLogger.info(
                    "{} | ip={} | user={} | transId={} | cif={} | status={}",
                    Instant.now(), clientIp,
                    decryptedUserId != null ? decryptedUserId : "UNAUTHORIZED",
                    decryptedTransId != null ? decryptedTransId : "UNKNOWN",
                    decryptedCif != null ? decryptedCif : "UNAUTHORIZED",
                    isSuccess ? "SUCCESS" : "FAILED"
            );
        }
    }

    private String secureHtml(String base64Image) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html oncontextmenu=\"return false;\"><head>")
            .append("<title>Document Viewer</title>")
            .append("<style>")
            .append("body { margin: 0; background: #1a1a1a; height: 100vh; display: flex; justify-content: center; align-items: center; overflow: auto; user-select: none; -webkit-user-select: none; }")
            .append(".img-container { padding: 20px; display: inline-block; }")
            .append("img { max-height: 90vh; pointer-events: none; box-shadow: 0 0 20px rgba(0,0,0,0.5); }")
            .append("@media print { body { display: none; } }")
            .append("</style></head>")
            .append("<body oncontextmenu=\"return false\" ondragstart=\"return false\" onselectstart=\"return false\">")
            .append("<div class=\"img-container\">")
            .append("<img src=\"data:image/png;base64,").append(base64Image).append("\" />")
            .append("</div>")
            .append("<script>")
            .append("document.addEventListener('keydown', function(e) {")
            .append("  if (e.ctrlKey && (e.key === 's' || e.key === 'p' || e.key === 'u' || e.keyCode === 83 || e.keyCode === 80 || e.keyCode === 85)) {")
            .append("    e.preventDefault(); alert('Action not allowed');")
            .append("  }")
            .append("});")
            .append("</script></body></html>");
        return html.toString();
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
        } catch (Exception e) { throw new RuntimeException("Decode Error"); }
    }

    static class HttpGetWithEntity extends HttpEntityEnclosingRequestBase {
        public static final String METHOD_NAME = "GET";
        public HttpGetWithEntity(String uri) { setURI(URI.create(uri)); }
        @Override public String getMethod() { return METHOD_NAME; }
    }
}