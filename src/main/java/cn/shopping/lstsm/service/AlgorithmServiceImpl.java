package cn.shopping.lstsm.service;

import cn.shopping.lstsm.entity.D3_Map;
import cn.shopping.lstsm.entity.MSK;
import cn.shopping.lstsm.utils.lsss.LSSSMatrix;
import cn.shopping.lstsm.utils.lsss.LSSSShares;
import cn.shopping.lstsm.utils.lsss.Vector;
import com.sun.scenario.effect.impl.sw.sse.SSEBlend_SRC_OUTPeer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.CORBA.PRIVATE_MEMBER;
import org.springframework.util.DigestUtils;

import java.util.Base64;

public class AlgorithmServiceImpl {
    private Pairing pairing;
    public static Field G1, GT, Zr, K;
    private Element g, alpha, lambda, tau, k1, k2, f, Y, Y0, h;
    private Element  s_1, s_11, u_1, u_11, u_111, D1, D2, D4;
    private Element[] D3, psi3, C3, C3_1;
    private Element psi1, psi2, psi4, psi5;
    private Element C0, C1, C2, C4, Cm;
    private Element T0, T1, T2, T3, T3_1, T4, T5;
    public MSK setup(){
        pairing = PairingFactory.getPairing("a.properties");
        PairingFactory.getInstance().setUsePBCWhenPossible(true);
        if(!pairing.isSymmetric()){
            throw new RuntimeException("密钥不对称");
        }

        Zr = pairing.getZr();
        G1 = pairing.getG1();
        K = pairing.getG2();
        GT = pairing.getGT();

        g = G1.newRandomElement().getImmutable();
        alpha = Zr.newRandomElement().getImmutable();
        lambda = Zr.newRandomElement().getImmutable();
        tau = Zr.newRandomElement().getImmutable();

        k1 = K.newRandomElement().getImmutable();
        k2 = K.newRandomElement().getImmutable();

        f = g.powZn(tau).getImmutable();
        Y = pairing.pairing(g, g).powZn(alpha).getImmutable();
        Y0 = pairing.pairing(g, f).getImmutable();
        h = g.powZn(lambda).getImmutable();

        MSK msk = new MSK();
        msk.setAlpha(alpha);
        msk.setLambda(lambda);
        msk.setTau(tau);
        msk.setK1(k1);
        msk.setK2(k2);

        return msk;
    }

    private Element a, r, rho;
    public void KeyGen(MSK msk, String id, String attributes[]){
        a = Zr.newRandomElement().getImmutable();
        r = Zr.newRandomElement().getImmutable();
        Element theta = Zr.newRandomElement().getImmutable();
        rho = Zr.newRandomElement().getImmutable();
        s_1 = Zr.newRandomElement().getImmutable();
        s_11 = Zr.newRandomElement().getImmutable();
        u_1 = Zr.newRandomElement().getImmutable();
        u_11 = Zr.newRandomElement().getImmutable();
        u_111 = Zr.newRandomElement().getImmutable();

        byte[] zeta_byte = Crytpto.SEnc(id.getBytes(), k1.toBytes());
        String zeta = Base64.getEncoder().encodeToString(zeta_byte);
        String delta_1 = zeta + theta.toString();
        byte[] delta_2 = Crytpto.SEnc(delta_1.getBytes(), k2.toBytes());
        Element delta= Zr.newElementFromBytes(delta_2).getImmutable();
        D1 = g.powZn((alpha.sub(a.mul(r))).div((lambda.add(delta)))).getImmutable();
        D2 = delta.getImmutable();

        int k = attributes.length;
        D3_Map[] D3 = new D3_Map[k];
        psi3 = new Element[k];
        for (int i = 0; i < k; i++) {
            String attributes_md5 = DigestUtils.md5DigestAsHex(attributes[i].getBytes());
            Element xi = Zr.newElementFromHash(attributes_md5.getBytes(),0,attributes_md5.length()).getImmutable();
            Element D3_t = g.powZn(a.mul(r).mul(xi.add(tau).invert())).getImmutable();
            D3_Map d3_t = new D3_Map();
            d3_t.setAttr(attributes[i]);
            d3_t.setD3(D3_t);
            D3[i] = d3_t;
            psi3[i] = (D3_t.powZn(rho)).powZn(u_11).getImmutable();
        }

        D4 = rho.getImmutable();

        psi1 = D1.powZn(rho.mulZn(u_1)).getImmutable();
        psi2 = Y0.powZn(u_111).getImmutable();
        psi4 = g.powZn(s_1).getImmutable();
        psi5 = f.powZn(s_11).getImmutable();
    }

    private byte[] CM;
    private Element gamma, s;
    private Element[] s_i;
    public void Enc(String msg, LSSSMatrix lsss, String KW) {
        gamma = GT.newRandomElement().getImmutable();
        String kse_t = DigestUtils.md5DigestAsHex(gamma.toBytes());
        Element kse = K.newElementFromBytes(kse_t.getBytes()).getImmutable();

        CM = Crytpto.SEnc(msg.getBytes(), kse.toBytes());
        s = Zr.newRandomElement().getImmutable();

        String attributes[] = lsss.getMap();
        int n = lsss.getMartix().getCols();
        int l = lsss.getMartix().getRows();
        Element[] Yn2 = new Element[n];//  get zr secret share matrix
        Yn2[0] = s.getImmutable();
        for(int i = 1 ; i < n; i++)
        {
            Yn2[i] = Zr.newRandomElement().getImmutable();
        }

        C3 = new Element[l];
        C3_1 = new Element[l];
        Vector secret2 = new Vector(false, Yn2);
        LSSSShares shares2 = lsss.genShareVector2(secret2);
        s_i = new Element[l];
        String kw_md5 = DigestUtils.md5DigestAsHex(KW.getBytes());
        Element HKW = Zr.newElementFromHash(kw_md5.getBytes(), 0, kw_md5.length()).getImmutable();
        for (int i = 0; i < l; i++) {
            s_i[i] = shares2.getVector().getValue2(i);
            String attributes_md5 = DigestUtils.md5DigestAsHex(attributes[i].getBytes());
            Element rou = Zr.newElementFromHash(attributes_md5.getBytes(),0,attributes_md5.length()).getImmutable();
            C3[i] = rou.mul(s_i[i]).div(s_1.mul(HKW)).getImmutable();
            C3_1[i] = s_i[i].div(s_11.mul(HKW)).getImmutable();
        }

        C0 = gamma.mul(Y.powZn(s)).getImmutable();
        C1 = g.powZn(s).getImmutable();
        C2 = h.powZn(s).getImmutable();
        C4 = Y0.powZn(HKW).mul(Y.powZn(s.div(HKW))).getImmutable();
    }

    private Element u,HKW_t, u0;
    public void Trapdoor(String KW){
        String kw_t_md5 = DigestUtils.md5DigestAsHex(KW.getBytes());
        HKW_t = Zr.newElementFromHash(kw_t_md5.getBytes(), 0, kw_t_md5.length()).getImmutable();

        u = Zr.newRandomElement().getImmutable();
        u0 = Zr.newRandomElement().getImmutable();

        T0 = u.mul(u_1.invert()).getImmutable();
        T1 = u0.div(u_1.mul(HKW_t)).getImmutable();
        T2 = D2.getImmutable();
        T3 = u0.mul(u_11.invert()).getImmutable();
        T3_1 = u.mul(HKW_t).mul(u_11.invert()).getImmutable();
        T4 = u0.mul(D4).getImmutable();
        T5 = u0.mul(D4).mul(HKW_t).mul(u_111.invert()).getImmutable();
    }

    private Element L, V;
    private Element V_verify,L_verify, s_verify, L2_verify, V2_verify, RightEq_verify;
    public boolean Test(LSSSMatrix lsssD1, int lsssIndex[]){
        Vector w_v = lsssD1.getRv();
        if(w_v == null){
            System.out.println("不符合要求");
            System.exit(0);
        }
        String[] user_attr = lsssD1.getMap();
        Element sum = G1.newElement().setToOne().getImmutable();
        Element sum2 = G1.newElement().setToOne().getImmutable();

        for (int i = 0; i < lsssD1.getMartix().getRows(); i++) {
            Element w = Zr.newElement(w_v.getValue(i)).getImmutable();
            sum = sum.mul(psi3[i].powZn(C3[i].mul(w))).getImmutable();
            sum2 = sum2.mul(psi3[i].powZn(C3_1[i].mul(w))).getImmutable();
        }



        V = pairing.pairing(psi4,sum).mul(pairing.pairing(psi5,sum2)).getImmutable();
      //  V_verify = pairing.pairing(g,g).powZn((a.mul(r).mul(rho).mul(u_11).mul(s)).div(HKW_t));


        L = pairing.pairing(psi1,C1.powZn(T2).mul(C2)).getImmutable();
       // L_verify = pairing.pairing(g,g).powZn((alpha.sub(a.mul(r))).mul(rho).mul(u_1).mul(s)).getImmutable();

        Element L2 = L.powZn(T1).getImmutable();
       // L2_verify = pairing.pairing(g,g).powZn((alpha.sub(a.mul(r))).mul(rho).mul(u0).mul(s).div(HKW_t)).getImmutable();


        Element V2 = V.powZn(T3).getImmutable();
        //V2_verify = pairing.pairing(g,g).powZn((a.mul(r).mul(rho).mul(u0).mul(s).div(HKW_t)));


        Element LeftEq = (psi2.powZn(T5)).mul(L2).mul(V2).getImmutable();
        Element RightEq = C4.powZn(T4).getImmutable();
        //RightEq_verify = (pairing.pairing(g,f).powZn(HKW_t.mul(u0).mul(rho))).mul(pairing.pairing(g,g).powZn(alpha.mul(s).mul(u0).mul(rho).div(HKW_t))).getImmutable();

        if (LeftEq.isEqual(RightEq)) {
            System.out.println("KW matched successfully,run next method");
            return true;
        }else{
            System.out.println("KW matched losely,please search another file");
            return false; //KW_1 != KW;
        }
    }

    private Element L1, V1;
    private Element L1_verify, V1_verify;
    public void Transform(){
        L1 = L.powZn(T0).getImmutable();
       // L1_verify = pairing.pairing(g,g).powZn((alpha.sub(a.mul(r))).mul(rho).mul(u).mul(s)).getImmutable();

        V1 = V.powZn(T3_1).getImmutable();
      //  V1_verify = pairing.pairing(g,g).powZn((a.mul(r).mul(rho).mul(u).mul(s)));

    }


    public byte[] Dec(){
        Element gamma_verify = C0.div((L1.mul(V1)).powZn(u.mul(D4).invert())).getImmutable();

      //  L1V1_verify = pairing.pairing(g,g).powZn(alpha.mul(rho).mul(u).mul(s));
        if (gamma_verify.equals(gamma)){
            // get gamma = get kse
            String kse_v = DigestUtils.md5DigestAsHex(gamma_verify.toBytes());
            Element kse_verify = K.newElementFromBytes(kse_v.getBytes()).getImmutable();
            byte[] m = Crytpto.SDec(CM,kse_verify.toBytes());
            return m;
        } else{
            System.out.println("get Deckey false");
            return null;
        }
    }
}
