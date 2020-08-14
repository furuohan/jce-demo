package jce.test;


import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;
import com.util.BytesUtil;

import javax.crypto.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.util.Arrays;

public class SM2Test {


    public static void main(String[] args) throws Exception{
        String data = "12345678901234567890";
        byte[] plain = data.getBytes();

        BaseProvider myprovider = new BaseProvider();    //申请provider
        Security.addProvider(myprovider);                    //嵌入provider
//        KeyPair keyPair = genkey(myprovider);
//        saveKeyFactory(keyPair.getPublic(),keyPair.getPrivate());
        KeyPair keyPair = readSM2Key();
        byte[] source = crypt(keyPair.getPublic(),myprovider,plain);
        decrypt(keyPair.getPrivate(),myprovider,source);

    }



    public static KeyPair genkey(BaseProvider myprovider) throws Exception{
        int outKeySize = 256;                        //设置key大小
        //获取钥匙对
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", myprovider);
        kpg.initialize(outKeySize);
        KeyPair outRSAKeyPair = kpg.genKeyPair();        //生成钥匙对
        return outRSAKeyPair;
    }

    public static void saveKeyFactory(PublicKey publicKey, PrivateKey privateKey) throws Exception{
        SimpleKeyStore simpleKeyStore = SimpleKeyStore.getInstance();
        simpleKeyStore.setKeyEntry("alias-sm2", new SimpleKeyStore.PublicAndPrivateKeyEntry(publicKey, privateKey, "123456".toCharArray()));
        // ....多个密钥
        simpleKeyStore.store(new FileOutputStream(new File("simple.keystore")), "111".toCharArray());
    }

    public static KeyPair readSM2Key ()throws Exception{

        SimpleKeyStore simpleKeyStore1 = SimpleKeyStore.load(new FileInputStream(new File("simple.keystore")), "111".toCharArray());
        SimpleKeyStore.PublicAndPrivateKeyEntry entry = (SimpleKeyStore.PublicAndPrivateKeyEntry) simpleKeyStore1.getKeyEntry("alias-sm2");

        PublicKey publicKey = entry.getPublicKey("123456".toCharArray());
        PrivateKey privateKey = entry.getPrivateKey("123456".toCharArray());

        KeyPair pair = new KeyPair(publicKey,privateKey);
        return pair;
    }

    public static byte[] crypt(PublicKey publicKey,Provider myprovider,byte[] plain) throws Exception{
        //开始加密过程
        Cipher cipher = Cipher.getInstance("SM2", myprovider);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        System.out.println("cipher"+cipher.toString());
        byte[] tTemp =  cipher.doFinal(plain);
        System.out.println("加密结果 length:"+tTemp.length+Arrays.toString(tTemp));
        System.out.println("加密str"+ BytesUtil.bytes2hex(tTemp));
        return tTemp;

    }

    public static byte[] decrypt(PrivateKey privateKey, Provider myprovider ,byte[] source) throws Exception{
        //开始解密过程
        Cipher  cipher = Cipher.getInstance("SM2", myprovider);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] tResult = cipher.doFinal(source);


        System.out.println("解密结果"+tResult.length + ":" + Arrays.toString(tResult));
        System.out.println("解密"+ new String(tResult));

        return tResult;
    }
}
