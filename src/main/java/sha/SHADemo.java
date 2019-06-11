package sha;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA算法学习
 *
 * @author zhanghao
 * @date 2019/06/11
 */
public class SHADemo {

    private static final String SRC = "Hello SHA";

    public static void main(String[] args) {
        sha1();
        ccSHA2();
    }


    private static void sha1() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(SRC.getBytes());
            System.out.println("SHA is : " + Hex.encodeHexString(md.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private static void ccSHA2() {
        System.out.println("SHA256 is : " + Hex.encodeHexString(DigestUtils.sha256(SRC)));
    }


}
