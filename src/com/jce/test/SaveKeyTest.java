package jce.test;

import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.Security;

public class SaveKeyTest {
    public static void main(String[] args) throws Exception{
        BaseProvider myprovider = new BaseProvider();    //申请provider
        Security.addProvider(myprovider);
        SimpleKeyStore simpleKeyStore = SimpleKeyStore.getInstance();
        // ....多个密钥

        //Sm1 key
        SecretKey sm1Key = SM1Test.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-sm1", new SimpleKeyStore.SecretKeyEntry(sm1Key, "123456".toCharArray()));
        //sm4 key
        SecretKey sm4Key = SM4Test.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-sm4", new SimpleKeyStore.SecretKeyEntry(sm4Key, "123456".toCharArray()));
        //aes key
        SecretKey aesKey = AESTest.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-aes", new SimpleKeyStore.SecretKeyEntry(aesKey, "123456".toCharArray()));
        //ssf33 key
        SecretKey ssf33Key = SSF33Test.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-ssf33", new SimpleKeyStore.SecretKeyEntry(ssf33Key, "123456".toCharArray()));

        //sm2 Key
        KeyPair sm2Key = SM2Test.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-sm2",
                new SimpleKeyStore.PublicAndPrivateKeyEntry(sm2Key.getPublic(), sm2Key.getPrivate(), "123456".toCharArray()));

        //rsa key
        KeyPair rsaKey = RSATest.genkey(myprovider);
        simpleKeyStore.setKeyEntry("alias-rsa",
                new SimpleKeyStore.PublicAndPrivateKeyEntry(rsaKey.getPublic(), rsaKey.getPrivate(), "123456".toCharArray()));

        simpleKeyStore.store(new FileOutputStream(new File("simple.keystore")), "111".toCharArray());

    }


}
