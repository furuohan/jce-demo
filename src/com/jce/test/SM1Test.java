package jce.test;


import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.util.Arrays;

public class SM1Test {

    public static void main(String[] args) throws Exception{
        //需要加密的数据
        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -31};
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};
        System.out.println(plain.length+":  "+plain.toString());
        String source ="待加密解密数据";
        BaseProvider myprovider = new BaseProvider();    //申请provider
        Security.addProvider(myprovider);                    //嵌入provider
        //获取钥匙对
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM1",myprovider);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println("algorithm:"+secretKey.getAlgorithm());
        System.out.println("key:"+ secretKey.getEncoded());
        byte[] encrypts = sm1Encrypt("SM1",plain,secretKey,myprovider);
        sm1Decrypt("SM1",encrypts,secretKey,myprovider);

        SimpleKeyStore simpleKeyStore = SimpleKeyStore.getInstance();
        simpleKeyStore.setKeyEntry("alias-sm1", new SimpleKeyStore.SecretKeyEntry(secretKey, "123456".toCharArray()));
        simpleKeyStore.setKeyEntry("alias-sm1-1", new SimpleKeyStore.SecretKeyEntry(secretKey, "123456".toCharArray()));
        simpleKeyStore.setKeyEntry("alias-sm1-2", new SimpleKeyStore.SecretKeyEntry(secretKey, "123456".toCharArray()));
        simpleKeyStore.store(new FileOutputStream(new File("simple.keystore")), "111".toCharArray());

        SimpleKeyStore simpleKeyStore1 = SimpleKeyStore.load(new FileInputStream(new File("simple.keystore")), "111".toCharArray());
        SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStore1.getKeyEntry("alias-sm1");
        SecretKey secretKey1 = entry.getSecretKey("123456".toCharArray());
        System.out.println(secretKey1);
    }

    public static byte[] sm1Encrypt(String type,byte[] source, SecretKey key, BaseProvider provider) throws Exception{
        //开始加密过程
        Cipher cipher = Cipher.getInstance(type, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] tTemp = cipher.doFinal(source);
        System.out.println("加密结果"+ Arrays.toString(tTemp));
        return tTemp;
    }

    public static void sm1Decrypt(String type, byte[] source, SecretKey key, BaseProvider provider) throws Exception{
        //开始解密过程
        Cipher cipher = Cipher.getInstance(type, provider);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] tResult = cipher.doFinal(source);
        System.out.println("解密结果"+tResult.length + ":" + Arrays.toString(tResult));

    }

}
