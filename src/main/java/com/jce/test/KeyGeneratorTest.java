package com.jce.test;

import com.provider.BaseProvider;
import com.util.BytesUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

/**
 * Created by fuxiaopeng on 2020-07-03.
 */
public class KeyGeneratorTest {
    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
        BaseProvider provider = new BaseProvider();
        Security.addProvider(provider);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES",provider);
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm());
        System.out.println(BytesUtil.bytes2hex(secretKey.getEncoded()));
    }
}
