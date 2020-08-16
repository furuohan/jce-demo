package com.jce.test;

import com.provider.BaseProvider;
import com.util.BytesUtil;

import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by fuxiaopeng on 2020-07-03.
 */
public class RandomTest {
    public static void main(String[] args) throws Exception {
        //对随机数进行测试setSeed
        BaseProvider provider = new BaseProvider();
        Security.addProvider(provider);
        SecureRandom secureRandom = SecureRandom.getInstance("RND",provider);

        byte[] seed = secureRandom.generateSeed(32);
        System.out.println(BytesUtil.bytes2int(seed));
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        System.out.println(BytesUtil.bytes2int(random));

    }
}
