package com.nbk;

import java.security.PublicKey;
import java.time.Instant;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Link Generator Tool — for development / testing only.
 *
 * Generates a valid signed URL that can be pasted into the browser
 * to test the secure image viewer without needing the real T24 system.
 *
 * Usage: GET /generate-link?cif=100205&userId=user01&transactionId=TXN999
 */
@RestController
public class LinkGeneratorController {

    @GetMapping(value = "/generate-link", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> generateLink(
            @RequestParam(name = "cif", defaultValue = "100205") String cif,
            @RequestParam(name = "userId", defaultValue = "user01") String userId,
            @RequestParam(name = "transactionId", defaultValue = "TXN999") String transactionId,
            HttpServletRequest request) {

        try {
            PublicKey publicKey = KeyLoader.loadPublicKey();

            String encCif = EncryptionOfTime.generateEncryptedToken(cif, publicKey);
            String encUserId = EncryptionOfTime.generateEncryptedToken(userId, publicKey);
            String encTransactionId = EncryptionOfTime.generateEncryptedToken(transactionId, publicKey);

            // Build the base URL from the incoming request so it works on any host/port
            String baseUrl = request.getScheme() + "://" + request.getServerName()
                    + ":" + request.getServerPort();

            String viewerUrl = baseUrl + "/?"
                    + "id=" + encCif
                    + "&transactionId=" + encTransactionId
                    + "&userId=" + encUserId;

            return ResponseEntity.ok(buildHtml(cif, userId, transactionId, viewerUrl));

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("<html><body><pre>Error: " + escapeHtml(e.getMessage()) + "</pre></body></html>");
        }
    }

    // ─── HTML ─────────────────────────────────────────────────────────────────

    private String buildHtml(String cif, String userId, String transId, String viewerUrl) {
        return "<!DOCTYPE html>\n"
                + "<html lang='en'>\n"
                + "<head>\n"
                + "  <meta charset='UTF-8'>\n"
                + "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
                + "  <title>🔗 Link Generator — Secure Viewer</title>\n"
                + "  <link rel='preconnect' href='https://fonts.googleapis.com'>\n"
                + "  <link href='https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap' rel='stylesheet'>\n"
                + "  <style>\n"
                + "    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }\n"
                + "    :root {\n"
                + "      --bg: #0d1117;\n"
                + "      --card: #161b22;\n"
                + "      --border: #30363d;\n"
                + "      --text: #e6edf3;\n"
                + "      --muted: #8b949e;\n"
                + "      --accent: #58a6ff;\n"
                + "      --accent-hover: #79b8ff;\n"
                + "      --green: #3fb950;\n"
                + "      --input-bg: #21262d;\n"
                + "    }\n"
                + "    html, body {\n"
                + "      min-height: 100vh;\n"
                + "      background: var(--bg);\n"
                + "      font-family: 'Inter', sans-serif;\n"
                + "      color: var(--text);\n"
                + "      display: flex;\n"
                + "      align-items: center;\n"
                + "      justify-content: center;\n"
                + "      padding: 24px;\n"
                + "    }\n"
                + "    .card {\n"
                + "      background: var(--card);\n"
                + "      border: 1px solid var(--border);\n"
                + "      border-radius: 12px;\n"
                + "      padding: 36px 40px;\n"
                + "      width: 100%;\n"
                + "      max-width: 780px;\n"
                + "      box-shadow: 0 0 40px rgba(0,0,0,0.5);\n"
                + "    }\n"
                + "    h1 {\n"
                + "      font-size: 1.5rem;\n"
                + "      font-weight: 700;\n"
                + "      color: var(--text);\n"
                + "      margin-bottom: 4px;\n"
                + "    }\n"
                + "    .subtitle {\n"
                + "      font-size: 0.875rem;\n"
                + "      color: var(--muted);\n"
                + "      margin-bottom: 28px;\n"
                + "    }\n"
                + "    .badge {\n"
                + "      display: inline-block;\n"
                + "      background: #1c2027;\n"
                + "      border: 1px solid #f78166;\n"
                + "      color: #f78166;\n"
                + "      font-size: 0.7rem;\n"
                + "      font-weight: 600;\n"
                + "      text-transform: uppercase;\n"
                + "      letter-spacing: .06em;\n"
                + "      padding: 2px 8px;\n"
                + "      border-radius: 20px;\n"
                + "      margin-left: 8px;\n"
                + "      vertical-align: middle;\n"
                + "    }\n"
                + "    .form-row {\n"
                + "      display: flex;\n"
                + "      gap: 16px;\n"
                + "      margin-bottom: 16px;\n"
                + "      flex-wrap: wrap;\n"
                + "    }\n"
                + "    .form-group {\n"
                + "      flex: 1;\n"
                + "      min-width: 180px;\n"
                + "    }\n"
                + "    label {\n"
                + "      display: block;\n"
                + "      font-size: 0.8rem;\n"
                + "      font-weight: 500;\n"
                + "      color: var(--muted);\n"
                + "      margin-bottom: 6px;\n"
                + "      text-transform: uppercase;\n"
                + "      letter-spacing: .05em;\n"
                + "    }\n"
                + "    input[type=text] {\n"
                + "      width: 100%;\n"
                + "      background: var(--input-bg);\n"
                + "      border: 1px solid var(--border);\n"
                + "      border-radius: 6px;\n"
                + "      padding: 10px 14px;\n"
                + "      color: var(--text);\n"
                + "      font-size: 0.9rem;\n"
                + "      font-family: inherit;\n"
                + "      outline: none;\n"
                + "      transition: border-color .2s;\n"
                + "    }\n"
                + "    input[type=text]:focus { border-color: var(--accent); }\n"
                + "    .btn {\n"
                + "      display: inline-flex;\n"
                + "      align-items: center;\n"
                + "      gap: 8px;\n"
                + "      background: var(--accent);\n"
                + "      color: #0d1117;\n"
                + "      font-weight: 600;\n"
                + "      font-size: 0.9rem;\n"
                + "      padding: 10px 22px;\n"
                + "      border: none;\n"
                + "      border-radius: 6px;\n"
                + "      cursor: pointer;\n"
                + "      text-decoration: none;\n"
                + "      transition: background .2s;\n"
                + "    }\n"
                + "    .btn:hover { background: var(--accent-hover); }\n"
                + "    .btn-ghost {\n"
                + "      background: transparent;\n"
                + "      border: 1px solid var(--border);\n"
                + "      color: var(--text);\n"
                + "    }\n"
                + "    .btn-ghost:hover { background: var(--input-bg); }\n"
                + "    .divider {\n"
                + "      border: none;\n"
                + "      border-top: 1px solid var(--border);\n"
                + "      margin: 28px 0;\n"
                + "    }\n"
                + "    .result-label {\n"
                + "      font-size: 0.78rem;\n"
                + "      font-weight: 600;\n"
                + "      color: var(--green);\n"
                + "      text-transform: uppercase;\n"
                + "      letter-spacing: .06em;\n"
                + "      margin-bottom: 10px;\n"
                + "    }\n"
                + "    .url-box {\n"
                + "      background: var(--input-bg);\n"
                + "      border: 1px solid var(--border);\n"
                + "      border-radius: 8px;\n"
                + "      padding: 14px 16px;\n"
                + "      font-family: 'SFMono-Regular', 'Consolas', monospace;\n"
                + "      font-size: 0.78rem;\n"
                + "      color: var(--muted);\n"
                + "      word-break: break-all;\n"
                + "      line-height: 1.6;\n"
                + "      position: relative;\n"
                + "      margin-bottom: 16px;\n"
                + "    }\n"
                + "    .url-box span.hi { color: var(--accent); }\n"
                + "    .actions { display: flex; gap: 10px; flex-wrap: wrap; }\n"
                + "    .info-row {\n"
                + "      display: flex;\n"
                + "      gap: 10px;\n"
                + "      margin-top: 20px;\n"
                + "      flex-wrap: wrap;\n"
                + "    }\n"
                + "    .chip {\n"
                + "      background: var(--input-bg);\n"
                + "      border: 1px solid var(--border);\n"
                + "      border-radius: 6px;\n"
                + "      padding: 6px 12px;\n"
                + "      font-size: 0.78rem;\n"
                + "      color: var(--muted);\n"
                + "    }\n"
                + "    .chip strong { color: var(--text); }\n"
                + "    #copy-msg {\n"
                + "      display: none;\n"
                + "      color: var(--green);\n"
                + "      font-size: 0.82rem;\n"
                + "      font-weight: 500;\n"
                + "      align-items: center;\n"
                + "      gap: 4px;\n"
                + "    }\n"
                + "    .expiry-note {\n"
                + "      font-size: 0.78rem;\n"
                + "      color: var(--muted);\n"
                + "      margin-top: 14px;\n"
                + "    }\n"
                + "    .expiry-note span { color: #f7c948; }\n"
                + "  </style>\n"
                + "</head>\n"
                + "<body>\n"
                + "<div class='card'>\n"
                + "  <h1>🔗 Secure Viewer — Link Generator <span class='badge'>DEV ONLY</span></h1>\n"
                + "  <p class='subtitle'>Generate a signed test URL for the secure document viewer. Valid for <strong style='color:var(--text)'>8 minutes</strong> after generation.</p>\n"
                + "\n"
                + "  <!-- FORM -->\n"
                + "  <form method='GET' action='/generate-link'>\n"
                + "    <div class='form-row'>\n"
                + "      <div class='form-group'>\n"
                + "        <label for='cif'>CIF (id)</label>\n"
                + "        <input id='cif' type='text' name='cif' value='" + escapeHtml(cif)
                + "' placeholder='e.g. 100205'>\n"
                + "      </div>\n"
                + "      <div class='form-group'>\n"
                + "        <label for='userId'>User ID</label>\n"
                + "        <input id='userId' type='text' name='userId' value='" + escapeHtml(userId)
                + "' placeholder='e.g. user01'>\n"
                + "      </div>\n"
                + "      <div class='form-group'>\n"
                + "        <label for='transactionId'>Transaction ID</label>\n"
                + "        <input id='transactionId' type='text' name='transactionId' value='" + escapeHtml(transId)
                + "' placeholder='e.g. TXN999'>\n"
                + "      </div>\n"
                + "    </div>\n"
                + "    <button type='submit' class='btn'>⚡ Generate New Link</button>\n"
                + "  </form>\n"
                + "\n"
                + "  <hr class='divider'>\n"
                + "\n"
                + "  <!-- RESULT -->\n"
                + "  <div class='result-label'>✅ Generated Link</div>\n"
                + "  <div class='url-box' id='url-text'>" + buildFormattedUrl(viewerUrl) + "</div>\n"
                + "\n"
                + "  <div class='actions'>\n"
                + "    <a href='" + escapeHtml(viewerUrl) + "' target='_blank' class='btn'>🚀 Open Viewer</a>\n"
                + "    <button class='btn btn-ghost' onclick='copyUrl()'>📋 Copy Link</button>\n"
                + "    <span id='copy-msg' style='display:none; color:var(--green); font-size:.82rem; align-items:center;'>✓ Copied!</span>\n"
                + "  </div>\n"
                + "\n"
                + "  <div class='info-row'>\n"
                + "    <div class='chip'>CIF: <strong>" + escapeHtml(cif) + "</strong></div>\n"
                + "    <div class='chip'>User ID: <strong>" + escapeHtml(userId) + "</strong></div>\n"
                + "    <div class='chip'>Transaction: <strong>" + escapeHtml(transId) + "</strong></div>\n"
                + "    <div class='chip'>Generated: <strong>" + Instant.now().toString().substring(0, 19)
                + "Z</strong></div>\n"
                + "  </div>\n"
                + "\n"
                + "  <p class='expiry-note'>⚠ <span>Tokens expire in 8 minutes</span> (5 min validity + 3 min clock-skew buffer). Regenerate if the link has expired.</p>\n"
                + "</div>\n"
                + "\n"
                + "<script>\n"
                + "  var rawUrl = " + toJsString(viewerUrl) + ";\n"
                + "  function copyUrl() {\n"
                + "    navigator.clipboard.writeText(rawUrl).then(function() {\n"
                + "      var msg = document.getElementById('copy-msg');\n"
                + "      msg.style.display = 'inline-flex';\n"
                + "      setTimeout(function() { msg.style.display = 'none'; }, 2000);\n"
                + "    });\n"
                + "  }\n"
                + "</script>\n"
                + "</body>\n"
                + "</html>\n";
    }

    /** Highlights the query-param keys in the URL box */
    private String buildFormattedUrl(String url) {
        // Split at '?' to highlight base vs params
        int q = url.indexOf('?');
        if (q < 0)
            return escapeHtml(url);
        String base = escapeHtml(url.substring(0, q + 1));
        String params = escapeHtml(url.substring(q + 1));
        // Highlight param names
        params = params
                .replaceFirst("(id=)", "<span class='hi'>$1</span>")
                .replaceFirst("(&amp;transactionId=)", "<span class='hi'>$1</span>")
                .replaceFirst("(&amp;userId=)", "<span class='hi'>$1</span>");
        return "<span style='color:var(--text)'>" + base + "</span>" + params;
    }

    private String escapeHtml(String s) {
        if (s == null)
            return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private String toJsString(String s) {
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'";
    }
}
