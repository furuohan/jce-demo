package jce.test;


import com.provider.BaseProvider;
import com.util.BytesUtil;

import java.security.*;

public class SignatureTest {
    public static void main(String[] args) throws Exception {
        KeyPair sm2Key = SM2Test.readSM2Key();
        KeyPair rsaKey = RSATest.readRSAKey();
//        SM3WithSM2(sm2Key);
//        SHA1WithSM2(sm2Key);
//        SHA224WithSM2(sm2Key);
//        SHA256WithSM2(sm2Key);
        SHA1WithRsa(rsaKey);
//        SHA224WithRsa(rsaKey);
//        SHA256WithRsa(rsaKey);
//        SHA384WithRsa(rsaKey);
//        SHA512WithRsa(rsaKey);
    }

    public static void SM3WithSM2(KeyPair keyPair) throws Exception{
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate().toString());
            Signature signature = Signature.getInstance("SM3WithSM2",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SM3WithSM2",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA1WithSM2(KeyPair keyPair) throws Exception{
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate().toString());
            Signature signature = Signature.getInstance("SHA1WithSM2",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA1WithSM2",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA224WithSM2(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate().toString());
            Signature signature = Signature.getInstance("SHA224WithSM2",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA224WithSM2",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA256WithSM2(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate().toString());
            Signature signature = Signature.getInstance("SHA256WithSM2",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA256WithSM2",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }


    public static void SHA1WithRsa(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate   ().toString());
            Signature signature = Signature.getInstance("SHA1WithRSA",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA1WithRSA",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA224WithRsa(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate   ().toString());
            Signature signature = Signature.getInstance("SHA224WithRSA",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA224WithRSA",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA256WithRsa(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate   ().toString());
            Signature signature = Signature.getInstance("SHA256WithRSA",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA256WithRSA",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA384WithRsa(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate   ().toString());
            Signature signature = Signature.getInstance("SHA384WithRSA",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA384WithRSA",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }

    public static void SHA512WithRsa(KeyPair keyPair){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            System.out.println(keyPair.getPublic().toString());
            System.out.println(keyPair.getPrivate   ().toString());
            Signature signature = Signature.getInstance("SHA512WithRSA",provider);  //进行签名

            signature.initSign(keyPair.getPrivate());       //传入钥匙

            signature.update(data.getBytes());      //传入数据

            byte[] out = signature.sign();        //进行签名

            System.out.println("签名length:"+out.length+"     " + BytesUtil.bytes2hex(out));
            //验签
            Signature signatureVerify = Signature.getInstance("SHA512WithRSA",provider);

            signatureVerify.initVerify(keyPair.getPublic());

            signatureVerify.update(data.getBytes());

            boolean flag = signatureVerify.verify(out);

            System.out.println("verify"+flag);
        }catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch (SignatureException e){
            e.printStackTrace();
        }catch (InvalidKeyException e){
            e.printStackTrace();
        }
    }
}
