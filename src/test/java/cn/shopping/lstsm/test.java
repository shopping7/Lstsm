package cn.shopping.lstsm;

import cn.shopping.lstsm.entity.*;
import cn.shopping.lstsm.service.AlgorithmServiceImpl;
import cn.shopping.lstsm.utils.lsss.LSSSEngine;
import cn.shopping.lstsm.utils.lsss.LSSSMatrix;
import it.unisa.dia.gas.jpbc.Element;

import java.util.HashMap;

public class test {
    public static void main(String[] args) {
        //        策略 a and (b or c) and (d or (e and f))


        //测试一
//        LSSSEngine engine = new LSSSEngine();
//        String policy = "hospital&(doctor|director)&(heart|(flu&headache))";
//        String[] attributes = {"hospital","doctor","director","heart","flu","headache"};
//        String[] attrs = {"hospital","doctor","heart"};
//        LSSSMatrix lsss = engine.genMatrix(policy);
//        System.out.println(lsss.toString());
//        LSSSMatrix lsssD1 = lsss.extract(attrs);
//        System.out.println(lsssD1);

        //测试二

//        String policy = "(医院|政府)&(医生|主任)&(心脏科|(流感&头疼))";
        String policy = "hospital&doctor&(headache|(flu&heart))";
        LSSSEngine engine = new LSSSEngine();
        LSSSMatrix lsss = engine.genMatrix(policy);

//        String[] user_attr = {"政府","医生","心脏科"};
        String[] user_attr = {"hospital","doctor","headache"};
        LSSSMatrix lsssD1 = lsss.extract(user_attr);
        int lsssIndex[] = lsssD1.getIndex();


        AlgorithmServiceImpl algorithmService = new AlgorithmServiceImpl();
        MSK msk = algorithmService.setup();
        String id = "id123";
        PKAndSK pkAndSK = algorithmService.KeyGen(msk, id, user_attr);
        SK sk = pkAndSK.getSk();
        PK pk = pkAndSK.getPk();
        String KW = "doctor";
        CT ct = algorithmService.Enc(sk, "crypto", lsss, KW);
        String KW1 = "doctor";
        Tkw trapdoor = algorithmService.Trapdoor(sk, KW1);
        boolean test = algorithmService.Test(pk, ct, trapdoor, lsssD1, lsssIndex);
        if(test){
            CTout CTout = algorithmService.Transform(ct, trapdoor, pk);
            byte[] bytes = algorithmService.Dec(CTout, sk);
            String str = new String(bytes);
            System.out.println(str);
        }
        if(algorithmService.KeySanityCheck(sk)){
            String id_re = algorithmService.Trace(msk, sk);
            System.out.println(id_re);
        }

    }
}
