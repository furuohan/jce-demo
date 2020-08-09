package jce.test;


import com.provider.BaseProvider;
import com.util.BytesUtil;

import java.security.*;

public class SignatureTest {
    public static void main(String[] args) throws Exception {
//        SM3WithSM2();
//        SHA1WithSM2();
        SHA224WithSM2();
//        SHA256WithSM2();
//        SHA1WithRsa();
//        SHA224WithRsa();
//        SHA256WithRsa();
//        SHA384WithRsa();
//        SHA512WithRsa();

    }

    public static void SM3WithSM2(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA1WithSM2(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2",provider); //生成SM2钥匙对
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA224WithSM2(){
        try{
            String data ="12345678912345612342141242131232";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2",provider); //生成SM2钥匙对
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA256WithSM2(){
        try{
            String data ="12345678912345612342141242131232";
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2",provider); //生成SM2钥匙对
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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


    public static void SHA1WithRsa(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA224WithRsa(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA256WithRsa(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA384WithRsa(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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

    public static void SHA512WithRsa(){
        try{
            String data ="12345678912345612342141242131232";            //只能32位
            BaseProvider provider = new BaseProvider();
            Security.addProvider(provider);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA",provider); //生成RSA钥匙对
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
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
