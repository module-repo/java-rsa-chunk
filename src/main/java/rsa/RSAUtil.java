package rsa;

import org.apache.commons.codec.binary.Base64;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtil {

    private static PublicKey getPublicKey(String rsaPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] keyBytes = rsaPublicKey.getBytes();

        String pem = new String(keyBytes);
        pem = pem.replace("-----BEGIN PUBLIC KEY-----", "");
        pem = pem.replace("-----END PUBLIC KEY-----", "");
        pem = pem.replace("\n", "");
        byte[] decoded = Base64.decodeBase64(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    // https://code84.com/2777.html
    private static PrivateKey getPrivateKey(String rsaPrivateKey) throws Exception {
        rsaPrivateKey = rsaPrivateKey.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replace("-----END RSA PRIVATE KEY-----", "");
        rsaPrivateKey = rsaPrivateKey.replaceAll("\\s+", "");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        DerInputStream derReader = new DerInputStream(Base64.decodeBase64(rsaPrivateKey));
        DerValue[] seq = derReader.getSequence(0);
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCOEf = seq[8].getBigInteger();
        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCOEf);
        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] Encrypt(byte[] data, String pubKey, int blockSize) throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(pubKey);
        Cipher cipher = Cipher.getInstance("RSA"); // cannot get block size
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        byte[] cache;
        int offSet = 0;

        int MAX_ENCRYPT_BLOCK = blockSize > 11 ? blockSize - 11 : 11;

        // 对数据分段加密
        int inputLen = data.length;
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }

        return out.toByteArray();
    }

    public static byte[] Decrypt(String enData, String priKey, int blockSize) throws Exception {
        byte[] data = Base64.decodeBase64(enData);
        PrivateKey privateKey = getPrivateKey(priKey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        byte[] cache;
        int offSet = 0;
        int inputLen = data.length;

        int MAX_DECRYPT_BLOCK = Math.max(blockSize, 11);

        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }

        byte[] decryptedData = out.toByteArray();
        out.close();

        return decryptedData;
    }
}