package org.example;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class JWTCreator2 {
    public String getEncryptedString( String data) throws Exception {

        String privateKeyString = replaceBeginEndBlocks(getResourceFileAsString("jwtRS256.key"));

        byte[] privateKeyStringAsBytes =  Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyStringAsBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey prvKey = kf.generatePrivate(keySpec);

        HashMap jwtClaims = new HashMap<String, String >();
        jwtClaims.put("data1", "The awesome guy");

        String jws = Jwts.builder()
                .setClaims(jwtClaims)
                .signWith(SignatureAlgorithm.RS256, prvKey)
                .compact();

        return jws;
    }

    public String getResourceFileAsString(String resourceFileName) throws Exception {
        URL urlResource =getClass().getClassLoader().getResource(resourceFileName);
        File publicKeyFile = new File(urlResource.toURI());
        String fileString = FileUtils.readFileToString(publicKeyFile, "UTF-8");
        return fileString;
    }

    public String replaceBeginEndBlocks(String key) {
        String refinedKey = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("\\n", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "");
        return refinedKey;
    }
}
