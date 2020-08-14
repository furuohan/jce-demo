package jce.test;


import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Arrays;

public class SM1Test {

    public static void main(String[] args) throws Exception{
        //需要加密的数据
        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -31};
        BaseProvider myprovider = new BaseProvider();    //申请provider
        Security.addProvider(myprovider);                    //嵌入provider

//        SecretKey key = genkey(myprovider);
//        saveKeyFactory(key);
        SecretKey key = readSM1Key();

        byte[] encrypts = sm1Encrypt("SM1",plain,key,myprovider);
        sm1Decrypt("SM1",encrypts,key,myprovider);
//
//
//
    }

    public static SecretKey genkey(BaseProvider myprovider) throws Exception{
        //获取钥匙对
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM1",myprovider);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    public static void saveKeyFactory(SecretKey secretKey) throws Exception{
        SimpleKeyStore simpleKeyStore = SimpleKeyStore.getInstance();
        simpleKeyStore.setKeyEntry("alias-sm1", new SimpleKeyStore.SecretKeyEntry(secretKey, "123456".toCharArray()));
        // ....多个密钥
        simpleKeyStore.store(new FileOutputStream(new File("simple.keystore")), "111".toCharArray());
    }

    public static SecretKey readSM1Key ()throws Exception{

        SimpleKeyStore simpleKeyStore1 = SimpleKeyStore.load(new FileInputStream(new File("simple.keystore")), "111".toCharArray());
        SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStore1.getKeyEntry("alias-sm1");
        SecretKey secretKey1 = entry.getSecretKey("123456".toCharArray());
        return secretKey1;
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
