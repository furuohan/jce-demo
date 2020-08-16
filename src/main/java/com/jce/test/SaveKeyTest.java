package com.jce.test;

import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.Security;

public class SaveKeyTest {
    public static void main(String[] args) throws Exception{
        BaseProvider myprovider = new BaseProvider();    //申请provider
        Security.addProvider(myprovider);

        //先读取keystore存储的密钥，相同别名，不更新密钥
        SimpleKeyStore simpleKeyStoreRead = SimpleKeyStore.load(new FileInputStream(new File("simple.keystore")), "111".toCharArray());

        SimpleKeyStore simpleKeyStore = SimpleKeyStore.getInstance();
        // ....多个密钥

        //Sm1 key
        if(simpleKeyStoreRead.getKeyEntry("alias-sm1") == null){
            System.out.println("sm1 不存在，重新存储密钥");
            SecretKey sm1Key = SM1Test.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-sm1", new SimpleKeyStore.SecretKeyEntry(sm1Key, "123456".toCharArray()));
        }else{
            SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-sm1");
            simpleKeyStore.setKeyEntry("alias-sm1",entry);
        }
        //sm4 key
        if(simpleKeyStoreRead.getKeyEntry("alias-sm4") == null){
            System.out.println("sm4 不存在，重新存储密钥");
            SecretKey sm4Key = SM4Test.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-sm4", new SimpleKeyStore.SecretKeyEntry(sm4Key, "123456".toCharArray()));
        }else{
            SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-sm4");
            simpleKeyStore.setKeyEntry("alias-sm4",entry);
        }

        //aes key
        if(simpleKeyStoreRead.getKeyEntry("alias-aes") == null){
            System.out.println("aes 不存在，重新存储密钥");
            SecretKey aesKey = AESTest.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-aes", new SimpleKeyStore.SecretKeyEntry(aesKey, "123456".toCharArray()));
        }else{
            SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-aes");
            simpleKeyStore.setKeyEntry("alias-aes",entry);
        }
        //ssf33 key
        if(simpleKeyStoreRead.getKeyEntry("alias-ssf33") == null){
            System.out.println("ssf33 不存在，重新存储密钥");
            SecretKey ssf33Key = SSF33Test.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-ssf33", new SimpleKeyStore.SecretKeyEntry(ssf33Key, "123456".toCharArray()));
        }else{
            SimpleKeyStore.SecretKeyEntry entry = (SimpleKeyStore.SecretKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-ssf33");
            simpleKeyStore.setKeyEntry("alias-ssf33",entry);
        }

        //sm2 Key
        if(simpleKeyStoreRead.getKeyEntry("alias-sm2") == null){
            System.out.println("sm2 不存在，重新存储密钥");
            KeyPair sm2Key = SM2Test.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-sm2",
                    new SimpleKeyStore.PublicAndPrivateKeyEntry(sm2Key.getPublic(), sm2Key.getPrivate(), "123456".toCharArray()));
        }else{
            SimpleKeyStore.PublicAndPrivateKeyEntry entry = (SimpleKeyStore.PublicAndPrivateKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-sm2");
            simpleKeyStore.setKeyEntry("alias-sm2",entry);
        }

        if(simpleKeyStoreRead.getKeyEntry("alias-rsa") == null){
            //rsa key
            System.out.println("rsa 不存在，重新存储密钥");
            KeyPair rsaKey = RSATest.genkey(myprovider);
            simpleKeyStore.setKeyEntry("alias-rsa",
                    new SimpleKeyStore.PublicAndPrivateKeyEntry(rsaKey.getPublic(), rsaKey.getPrivate(), "123456".toCharArray()));
        }else{
            SimpleKeyStore.PublicAndPrivateKeyEntry entry = (SimpleKeyStore.PublicAndPrivateKeyEntry) simpleKeyStoreRead.getKeyEntry("alias-rsa");
            simpleKeyStore.setKeyEntry("alias-rsa",entry);
        }


        simpleKeyStore.store(new FileOutputStream(new File("simple.keystore")), "111".toCharArray());

    }


}
