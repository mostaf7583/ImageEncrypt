package com.nbk;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyLoader {
	public static PrivateKey loadPrivateKey() throws Exception {
		try (InputStream is = KeyLoader.class.getResourceAsStream("/keys/private_key.pem")) {
			String key = new String(toByteArray(is)).replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
			byte[] decoded = Base64.getDecoder().decode(key);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
			return KeyFactory.getInstance("RSA").generatePrivate(spec);
		}
	}

	public static byte[] toByteArray(InputStream is) throws IOException {
	    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	    byte[] data = new byte[1024];
	    int nRead;
	    while ((nRead = is.read(data, 0, data.length)) != -1) {
	        buffer.write(data, 0, nRead);
	    }
	    return buffer.toByteArray();
	}


	public static PublicKey loadPublicKey() throws Exception {
		try (InputStream is = KeyLoader.class.getResourceAsStream("/keys/public_key.pem")) {
			if (is == null)
				throw new FileNotFoundException("Public key file not found in resources");

			// Java 8 compatible way to read all bytes
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			int nRead;
			byte[] data = new byte[16384];
			while ((nRead = is.read(data, 0, data.length)) != -1) {
				buffer.write(data, 0, nRead);
			}

			String key = new String(buffer.toByteArray(), StandardCharsets.UTF_8)
					.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")
					.replaceAll("\\s", "");

			byte[] decoded = Base64.getDecoder().decode(key);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
			return KeyFactory.getInstance("RSA").generatePublic(spec);
		}
	}
}
