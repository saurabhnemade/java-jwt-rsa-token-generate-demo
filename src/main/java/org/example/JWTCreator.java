package org.example;

import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static com.sun.org.apache.xml.internal.security.utils.Base64.encode;


public class JWTCreator {

    private static String header = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    public void getEncryptedString(String data) throws Exception {
        String publicKeyString = replaceBeginEndBlocks(getResourceFileAsString("jwtRS256.key.pub"));
        String privateKeyString = replaceBeginEndBlocks(getResourceFileAsString("jwtRS256.key"));

        byte[] publicKeyStringAsBytes =  Base64.getDecoder().decode(publicKeyString);
        byte[] privateKeyStringAsBytes =  Base64.getDecoder().decode(privateKeyString);

        byte[] keyBytesToUse = privateKeyStringAsBytes;

//        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytesToUse);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PublicKey cipherUsableKey = kf.generatePublic(spec);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytesToUse);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey cipherUsableKey = kf.generatePrivate(keySpec);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, cipherUsableKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        String base64EncryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("output");
        System.out.println(base64EncryptedString);

        String base64EncodedHeader = Base64.getEncoder().encodeToString(header.getBytes());
        String encodedPartOneData = base64EncodedHeader + "." + base64EncryptedString;
        String signature = hmacSha256(encodedPartOneData.getBytes(), keyBytesToUse);

        System.out.println("final");
        System.out.println(encodedPartOneData + "." + signature);
    }

    private String hmacSha256(byte[] data, byte[] secret) throws Exception{
        try {

            byte[] hash = secret;
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data);

            return encode(signedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            return null;
        }
    }


    public String getResourceFileAsString(String resourceFileName) throws Exception {
        URL urlResource =getClass().getClassLoader().getResource(resourceFileName);
        File publicKeyFile = new File(urlResource.toURI());
        String publicKeyString = FileUtils.readFileToString(publicKeyFile, "UTF-8");
        return publicKeyString;
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
