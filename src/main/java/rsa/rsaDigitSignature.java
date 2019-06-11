package rsa;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA 数字签名
 *
 * @author zhanghao
 * @date 2019/06/11
 */
public class rsaDigitSignature {

    private static final String SRC = "Hello RSA";

    public static void main(String[] args) {
        rsaSign();
    }


    public static void rsaSign() {

        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            //初始化密钥长度
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            //私钥
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();


            System.out.println("public key:" + Base64.encodeBase64String(rsaPublicKey.getEncoded()));
            System.out.println("private key:" + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));


            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(SRC.getBytes());
            byte[] sign = signature.sign();
            System.out.println("rsa sign :" + Hex.encodeHexString(sign));


            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(SRC.getBytes());
            boolean verify = signature.verify(sign);

            System.out.println("verify:" + verify);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
