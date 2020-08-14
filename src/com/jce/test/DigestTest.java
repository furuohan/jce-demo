package jce.test;


import com.provider.BaseProvider;
import com.util.BytesUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class DigestTest {
    public static void main(String[] args) {
        md5Test();
//        sm3Test();
//        sha1Test();
//        SHA224Test();
//        SHA256Test();
//        SHA384Test();
//        SHA512Test();
//        SHA3224Test();
//        SHA3256Test();
//        SHA3384Test();
//        SHA3512Test();
//        SM3WithIDTest();
//        SM3WithoutIDTest();
    }

    public static void md5Test(){
        try{
            String input2 = "原始数据原始数据";
            BaseProvider provider2 = new BaseProvider();
            Security.addProvider(provider2);
            MessageDigest messageDigest2 = MessageDigest.getInstance("MD5", provider2);
            messageDigest2.update(input2.getBytes());
            byte[] output2 = messageDigest2.digest();
            System.out.println(output2.length); System.out.println(BytesUtil.bytes2hex(output2));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void sm3Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SM3", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void sha1Test(){
        try{
            String input = "12345678912345612342141242131232";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA1", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA224Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA224", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA256Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA384Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA384", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA512Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA512", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA3224Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA3224", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA3256Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA3256", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA3384Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA3384", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SHA3512Test(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA3512", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SM3WithIDTest(){
        try{
            String input = "原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SM3WithID", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    public static void SM3WithoutIDTest(){
        try{
            String input = "原始数据";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            MessageDigest messageDigest = MessageDigest.getInstance("SM3WithoutID", provider);
            messageDigest.update(input.getBytes());
            byte[] output = messageDigest.digest();
            System.out.println(output.length); System.out.println(BytesUtil.bytes2hex(output));
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }
}
