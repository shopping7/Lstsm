package cn.shopping.lstsm;

import cn.shopping.lstsm.entity.MSK;
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
        String id = "id";
        algorithmService.KeyGen(msk,id,user_attr);
        String KW = "doctor";
        algorithmService.Enc("crypto",lsss, KW);
        String KW1 = "doctor";
        algorithmService.Trapdoor(KW1);
        boolean test = algorithmService.Test(lsssD1, lsssIndex);
        if(test){
            algorithmService.Transform();
            byte[] bytes = algorithmService.Dec();
            String str = new String(bytes);
            System.out.println(str);
        }


    }
}
