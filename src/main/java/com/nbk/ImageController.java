package com.nbk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;

import javax.imageio.ImageIO;
import javax.net.ssl.SSLContext;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RestController
public class ImageController {

    private static final Logger logger = LoggerFactory.getLogger(ImageController.class);
    private final CloseableHttpClient httpClient;

    @Value("${app.laserfiche.url}")
    private String laserficheUrl;

    @Value("${app.laserfiche.auth-header}")
    private String authHeader;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ImageController() {
        try {
            // Create a trust manager that does not validate certificate chains
            SSLContext sslContext = new SSLContextBuilder()
                    .loadTrustMaterial(null, (certificate, authType) -> true)
                    .build();

            // Create an HttpClient that trusts all certs (comparable to the user's snippet)
            this.httpClient = HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create unsafe HttpClient", e);
        }
    }

    @GetMapping("/")
    public ResponseEntity<byte[]> getImage(@RequestParam(name = "id", required = false) String id) {
        logger.info("Received request for Document ID: {}", id);

        if (id == null || id.isEmpty()) {
            return ResponseEntity.badRequest().body("Missing 'id' parameter".getBytes());
        }

        try {
            logger.info("Attempting to fetch from upstream URL: {}", laserficheUrl);

            // Hardcoded CaseID as requested
            String jsonBody = "{\n" +
                    "    \"CaseID\": \"8732\",\n" +
                    "    \"RequestID\" : \"\",\n" +
                    "    \"DocumentType\": \"national id\"\n" +
                    "}";

            // Java 8 compatible "GET with Body" using Apache HttpClient
            HttpGetWithEntity request = new HttpGetWithEntity(laserficheUrl);
            request.setEntity(new StringEntity(jsonBody, StandardCharsets.UTF_8));
            request.setHeader("Authorization", authHeader);
            request.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();
                logger.info("Upstream response code: {}", statusCode);

                if (statusCode == 200) {
                    HttpEntity entity = response.getEntity();
                    String respBody = entity != null ? EntityUtils.toString(entity, StandardCharsets.UTF_8) : "";
                    logger.info("Upstream response body length: {}", respBody.length());
                    byte[] pdfBytes = extractAndDecodePdf(respBody);
                    byte[] imageBytes = convertPdfToImage(pdfBytes);

                    logger.info("Successfully converted PDF to Image. Size: {} bytes", imageBytes.length);
                    return ResponseEntity.ok()
                            .contentType(MediaType.IMAGE_PNG)
                            .header("Content-Disposition", "inline; filename=\"document.png\"")
                            .body(imageBytes);
                } else {
                    logger.error("Upstream failed with status {}. Returning error.", statusCode);
                    return ResponseEntity.status(statusCode)
                            .body(("Upstream failed with status " + statusCode).getBytes());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing request", e);
            return ResponseEntity.internalServerError().body(("Error fetching document: " + e.getMessage()).getBytes());
        }
    }

    private byte[] extractAndDecodePdf(String json) {
        try {
            if (json == null || json.trim().isEmpty()) {
                throw new RuntimeException("Response body is empty");
            }
            JsonNode rootNode = objectMapper.readTree(json);
            JsonNode streamBytesNode = rootNode.get("StreamBytes");

            if (streamBytesNode != null && !streamBytesNode.isNull()) {
                String base64 = streamBytesNode.asText();
                return Base64.getDecoder().decode(base64);
            }
            throw new RuntimeException(
                    "StreamBytes not found in response JSON: " + json.substring(0, Math.min(json.length(), 200)));
        } catch (Exception e) {
            String preview = json != null ? json.substring(0, Math.min(json.length(), 200)) : "null";
            logger.error("Failed to parse JSON response. Content preview: {}", preview);
            throw new RuntimeException("Failed to parse JSON response. Content: " + preview, e);
        }
    }

    private byte[] convertPdfToImage(byte[] pdfBytes) throws Exception {
        try (PDDocument document = PDDocument.load(pdfBytes)) {
            int pageCount = document.getNumberOfPages();
            if (pageCount == 0) {
                throw new RuntimeException("PDF has no pages");
            }

            PDFRenderer renderer = new PDFRenderer(document);
            List<BufferedImage> images = new ArrayList<>();
            int totalWidth = 0;
            int maxHeight = 0;

            // Render all pages
            for (int i = 0; i < pageCount; i++) {
                // Render each page at 150 DPI (lower native DPI for performance/memory,
                // but quality usually sufficient for side-by-side)
                // or stick to 300 if high quality is mandatory.
                // Using 300 as per previous logic.
                BufferedImage image = renderer.renderImageWithDPI(i, 300, ImageType.RGB);
                images.add(image);
                totalWidth += image.getWidth();
                if (image.getHeight() > maxHeight) {
                    maxHeight = image.getHeight();
                }
            }

            // Stitch images side-by-side
            BufferedImage combinedImage = new BufferedImage(totalWidth, maxHeight, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2d = combinedImage.createGraphics();

            int currentX = 0;
            for (BufferedImage image : images) {
                g2d.drawImage(image, currentX, 0, null);
                currentX += image.getWidth();
            }
            g2d.dispose();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(combinedImage, "png", baos);
            return baos.toByteArray();
        }
    }

    // Inner class to allow GET with body
    static class HttpGetWithEntity extends HttpEntityEnclosingRequestBase {
        public final static String METHOD_NAME = "GET";

        public HttpGetWithEntity(final String uri) {
            super();
            setURI(URI.create(uri));
        }

        @Override
        public String getMethod() {
            return METHOD_NAME;
        }
    }
}
