package com.jce.test;


import com.provider.BaseProvider;
import com.util.BytesUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class MacTest {
    public static void main(String[] args) {
        sm1Test();
        sm4Test();
    }

    private static void sm1Test()  {
        try{
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM1",provider);
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            // String input = "原始数据";
            byte plain[] = {(byte) 0xe8,(byte)0x3d,(byte)0x17,(byte)0x15,(byte)0xac,(byte)0xf3,
                    (byte)0x48,(byte)0x63,(byte)0xac,(byte)0xeb,(byte)0x93,
                    (byte)0xe0,(byte)0xe5,(byte)0xab,(byte)0x8b,(byte)0x90};
            Mac mac = Mac.getInstance("MACSM1",provider);

            mac.init(key);

            mac.update(plain);

            byte[] output = mac.doFinal();

            System.out.println(output.length);
            System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }

    }

    private static void sm4Test() {
        try{
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyGenerator keyGenerator = KeyGenerator.getInstance("SMS4",provider);
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            // String input = "原始数据";
            byte plain[] = {(byte) 0xe8,(byte)0x3d,(byte)0x17,(byte)0x15,(byte)0xac,(byte)0xf3,
                    (byte)0x48,(byte)0x63,(byte)0xac,(byte)0xeb,(byte)0x93,
                    (byte)0xe0,(byte)0xe5,(byte)0xab,(byte)0x8b,(byte)0x90};
            Mac mac = Mac.getInstance("MACSMS4",provider);

            mac.init(key);

            mac.update(plain);

            byte[] output = mac.doFinal();

            System.out.println(output.length);
            System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }

    }
}
