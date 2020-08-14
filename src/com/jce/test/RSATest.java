package jce.test;


import com.keystore.JceKeyStore;
import com.keystore.SimpleKeyStore;
import com.provider.BaseProvider;
import com.util.JCEConstant;
import jdk.internal.util.xml.impl.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.util.Arrays;

public class RSATest {


	public static void main(String[] args) throws Exception{

		BaseProvider myprovider = new BaseProvider();	//申请provider
		Security.addProvider(myprovider);//嵌入provider

		//读取公私钥
		KeyPair keyPair = readRSAKey();
		//需要加密的数据
		byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};

		//加密
		byte[] temp = crypt(keyPair.getPublic(),myprovider,plain);
		//解密
		decrypt(keyPair.getPrivate(),myprovider,temp);

	}

	public static KeyPair genkey(BaseProvider myprovider) throws Exception{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", myprovider);
		kpg.initialize(1024);
		KeyPair keyPair = kpg.generateKeyPair();
		return keyPair;
	}


	public static KeyPair readRSAKey ()throws Exception{
        SimpleKeyStore simpleKeyStore1 = SimpleKeyStore.load(new FileInputStream(new File("simple.keystore")), "111".toCharArray());
        SimpleKeyStore.PublicAndPrivateKeyEntry entry = (SimpleKeyStore.PublicAndPrivateKeyEntry) simpleKeyStore1.getKeyEntry("alias-rsa");
        PublicKey publicKey2 = entry.getPublicKey("123456".toCharArray());
        PrivateKey privateKey2 = entry.getPrivateKey("123456".toCharArray());
        KeyPair pair = new KeyPair(publicKey2,privateKey2);
        return pair;
    }

	public static byte[] crypt(PublicKey publicKey,Provider myprovider,byte[] plain){
		//开始加密过程
		try{
			Cipher cipher = Cipher.getInstance("RSA", myprovider);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] tTemp = cipher.doFinal(plain);
			System.out.println("加密后数据"+Arrays.toString(tTemp));
			return tTemp;
		}catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e ){
			e.printStackTrace();
			return null;
		}

	}

	public static byte[] decrypt(PrivateKey privateKey, Provider myprovider ,byte[] source) throws Exception{
		//开始解密过程
		Cipher cipher = Cipher.getInstance("RSA", myprovider);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] tResult = cipher.doFinal(source);
		System.out.println("解密后的数据:"+Arrays.toString(tResult));
		return tResult;
	}

}
