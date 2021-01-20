package cn.shopping.lstsm;


import cn.shopping.lstsm.service.AlgorithmServiceImpl;
import cn.shopping.lstsm.utils.lsss.LSSSEngine;
import cn.shopping.lstsm.utils.lsss.LSSSMatrix;
import cn.shopping.lstsm.utils.lsss.LSSSShares;
import cn.shopping.lstsm.utils.lsss.Vector;
import it.unisa.dia.gas.jpbc.Element;

public class lsssTest {
    public static void main(String[] args) {

        AlgorithmServiceImpl algorithmService = new AlgorithmServiceImpl();
        algorithmService.setup();
        String policy = "hospital&doctor&(headache|(flu&heart))";
        LSSSEngine engine = new LSSSEngine();
        LSSSMatrix lsss = engine.genMatrix(policy);

        Element s = algorithmService.Zr.newRandomElement().getImmutable();
        Element[] Yn2 = new Element[lsss.getMartix().getCols()];//  get zr secret share matrix
        Yn2[0] = s.getImmutable();
        for(int i = 1 ; i < Yn2.length; i++)
        {
            Yn2[i] = algorithmService.Zr.newRandomElement().getImmutable();
        }
        Vector secret2 = new Vector(false, Yn2);
        LSSSShares shares2 = lsss.genShareVector2(secret2);

        Element[] lambda_i = new Element[lsss.getMartix().getRows()];
        for (int i = 0; i < lambda_i.length; i++) {
            lambda_i[i] = shares2.getVector().getValue2(i).getImmutable();
        }


        //        String[] user_attr = {"政府","医生","心脏科"};
        String[] user_attr = {"hospital","doctor","headache"};
        LSSSMatrix lsssD1 = lsss.extract(user_attr);
        int lsssIndex[] = lsssD1.getIndex();
        Vector w = lsssD1.getRv();
//        Element s_verify = (lambda_i[0].mul(Zr.newElement(w.getValue(0)))).add(lambda_i[1].mul(Zr.newElement(w.getValue(1)))).add(lambda_i[2].mul(Zr.newElement(w.getValue(2))));
        Element s_verify = algorithmService.Zr.newElement().setToZero().getImmutable();

        for (int i = 0; i < lsssD1.getMartix().getRows(); i++) {
            s_verify = s_verify.add(lambda_i[lsssIndex[i]].mul(algorithmService.Zr.newElement(w.getValue(i)))).getImmutable();
        }
        if(s.equals(s_verify)){
            System.out.println("equal");
        }
    }
}
