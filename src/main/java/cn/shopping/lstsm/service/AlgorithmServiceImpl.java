package cn.shopping.lstsm.service;

import cn.shopping.lstsm.entity.*;
import cn.shopping.lstsm.utils.lsss.LSSSMatrix;
import cn.shopping.lstsm.utils.lsss.LSSSShares;
import cn.shopping.lstsm.utils.lsss.Vector;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.springframework.util.DigestUtils;

import java.util.Base64;

public class AlgorithmServiceImpl {
    private Pairing pairing;
    public static Field G1, GT, Zr, K;
    private Element g, f, Y, Y0, h;
    private Element L,V; //云服务器存储
    private Element gamma, u; //用户端存储

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
        Element alpha = Zr.newRandomElement().getImmutable();
        Element lambda = Zr.newRandomElement().getImmutable();
        Element tau = Zr.newRandomElement().getImmutable();

        Element k1 = K.newRandomElement().getImmutable();
        Element k2 = K.newRandomElement().getImmutable();

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

    public PKAndSK KeyGen(MSK msk, String id, String attributes[]){
        Element k1 = msk.getK1();
        Element k2 = msk.getK2();
        Element lambda = msk.getLambda();
        Element alpha = msk.getAlpha();
        Element tau = msk.getTau();
        Element a = Zr.newRandomElement().getImmutable();
        Element r = Zr.newRandomElement().getImmutable();
        Element theta = Zr.newRandomElement().getImmutable();
        Element rho = Zr.newRandomElement().getImmutable();
        Element s_1 = Zr.newRandomElement().getImmutable();
        Element s_11 = Zr.newRandomElement().getImmutable();
        Element u_1 = Zr.newRandomElement().getImmutable();
        Element u_11 = Zr.newRandomElement().getImmutable();
        Element u_111 = Zr.newRandomElement().getImmutable();

        byte[] zeta_byte = Crytpto.SEnc(id.getBytes(), k1.toBytes());
        String zeta = Base64.getEncoder().encodeToString(zeta_byte);
        String delta_1 = zeta + theta.toString();
        byte[] delta_2 = Crytpto.SEnc(delta_1.getBytes(), k2.toBytes());
        String delta_s = Base64.getEncoder().encodeToString(delta_2);
        Element delta= Zr.newElementFromBytes(delta_2).getImmutable();
        Element D1 = g.powZn((alpha.sub(a.mul(r))).div((lambda.add(delta)))).getImmutable();
        Element D2 = delta.getImmutable();

        int k = attributes.length;
        D3_Map[] D3 = new D3_Map[k];
        Element[] psi3 = new Element[k];
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

        Element D4 = rho.getImmutable();

        Element psi1 = D1.powZn(rho.mulZn(u_1)).getImmutable();
        Element psi2 = Y0.powZn(u_111).getImmutable();
        Element psi4 = g.powZn(s_1).getImmutable();
        Element psi5 = f.powZn(s_11).getImmutable();

        PK pk = new PK();
        pk.setPsi1(psi1);
        pk.setPsi2(psi2);
        pk.setPsi3(psi3);
        pk.setPsi4(psi4);
        pk.setPsi5(psi5);

        SK sk = new SK();
        sk.setD1(D1);
        sk.setD2(D2);
        sk.setD3(D3);
        sk.setD4(D4);
        sk.setS_1(s_1);
        sk.setS_11(s_11);
        sk.setU_1(u_1);
        sk.setU_11(u_11);
        sk.setU_111(u_111);
        sk.setDelta_s(delta_s);
        sk.setTheta(theta);

        PKAndSK pkAndsk = new PKAndSK();
        pkAndsk.setPk(pk);
        pkAndsk.setSk(sk);

        return pkAndsk;
    }


    public CT Enc(SK sk,String msg, LSSSMatrix lsss, String KW) {
        Element s_1 = sk.getS_1();
        Element s_11 = sk.getS_11();
        gamma = GT.newRandomElement().getImmutable();
        String kse_t = DigestUtils.md5DigestAsHex(gamma.toBytes());
        Element kse = K.newElementFromBytes(kse_t.getBytes()).getImmutable();

        byte[] CM = Crytpto.SEnc(msg.getBytes(), kse.toBytes());
        Element s = Zr.newRandomElement().getImmutable();

        String attributes[] = lsss.getMap();
        int n = lsss.getMartix().getCols();
        int l = lsss.getMartix().getRows();
        Element[] Yn2 = new Element[n];//  get zr secret share matrix
        Yn2[0] = s.getImmutable();
        for(int i = 1 ; i < n; i++)
        {
            Yn2[i] = Zr.newRandomElement().getImmutable();
        }

        Element[] C3 = new Element[l];
        Element[] C3_1 = new Element[l];
        Vector secret2 = new Vector(false, Yn2);
        LSSSShares shares2 = lsss.genShareVector2(secret2);
        Element[] s_i = new Element[l];
        String kw_md5 = DigestUtils.md5DigestAsHex(KW.getBytes());
        Element HKW = Zr.newElementFromHash(kw_md5.getBytes(), 0, kw_md5.length()).getImmutable();
        for (int i = 0; i < l; i++) {
            s_i[i] = shares2.getVector().getValue2(i);
            String attributes_md5 = DigestUtils.md5DigestAsHex(attributes[i].getBytes());
            Element rou = Zr.newElementFromHash(attributes_md5.getBytes(),0,attributes_md5.length()).getImmutable();
            C3[i] = rou.mul(s_i[i]).div(s_1.mul(HKW)).getImmutable();
            C3_1[i] = s_i[i].div(s_11.mul(HKW)).getImmutable();
        }

        Element C0 = gamma.mul(Y.powZn(s)).getImmutable();
        Element C1 = g.powZn(s).getImmutable();
        Element C2 = h.powZn(s).getImmutable();
        Element C4 = Y0.powZn(HKW).mul(Y.powZn(s.div(HKW))).getImmutable();

        CT ct = new CT();
        ct.setC0(C0);
        ct.setC1(C1);
        ct.setC2(C2);
        ct.setC3(C3);
        ct.setC3_1(C3_1);
        ct.setC4(C4);
        ct.setCm(CM);

        return ct;
    }


    public Tkw Trapdoor(SK sk,String KW){
        Element D2 = sk.getD2();
        Element D4 = sk.getD4();
        Element u_1 = sk.getU_1();
        Element u_11 = sk.getU_11();
        Element u_111 = sk.getU_111();

        String kw_t_md5 = DigestUtils.md5DigestAsHex(KW.getBytes());
        Element HKW_t = Zr.newElementFromHash(kw_t_md5.getBytes(), 0, kw_t_md5.length()).getImmutable();

        u = Zr.newRandomElement().getImmutable();
        Element u0 = Zr.newRandomElement().getImmutable();

        Element T0 = u.mul(u_1.invert()).getImmutable();
        Element T1 = u0.div(u_1.mul(HKW_t)).getImmutable();
        Element T2 = D2.getImmutable();
        Element T3 = u0.mul(u_11.invert()).getImmutable();
        Element T3_1 = u.mul(HKW_t).mul(u_11.invert()).getImmutable();
        Element T4 = u0.mul(D4).getImmutable();
        Element T5 = u0.mul(D4).mul(HKW_t).mul(u_111.invert()).getImmutable();

        Tkw Tkw = new Tkw();
        Tkw.setT0(T0);
        Tkw.setT1(T1);
        Tkw.setT2(T2);
        Tkw.setT3(T3);
        Tkw.setT3_1(T3_1);
        Tkw.setT4(T4);
        Tkw.setT5(T5);
        return Tkw;
    }


    public boolean Test(PK pk, CT ct, Tkw Tkw, LSSSMatrix lsssD1, int lsssIndex[]){
        Element psi1 = pk.getPsi1();
        Element psi2 = pk.getPsi2();
        Element[] psi3 = pk.getPsi3();
        Element psi4 = pk.getPsi4();
        Element psi5 = pk.getPsi5();
        Element C1 = ct.getC1();
        Element C2 = ct.getC2();
        Element[] C3 = ct.getC3();
        Element[] C3_1 = ct.getC3_1();
        Element C4 = ct.getC4();
        Element T1 = Tkw.getT1();
        Element T2 = Tkw.getT2();
        Element T3 = Tkw.getT3();
        Element T4 = Tkw.getT4();
        Element T5 = Tkw.getT5();
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

    public CTout Transform(CT ct, Tkw Tkw, PK pk){
        Element T0 = Tkw.getT0();
        Element T3_1 = Tkw.getT3_1();

        Element L1 = L.powZn(T0).getImmutable();
       // L1_verify = pairing.pairing(g,g).powZn((alpha.sub(a.mul(r))).mul(rho).mul(u).mul(s)).getImmutable();

        Element V1 = V.powZn(T3_1).getImmutable();
      //  V1_verify = pairing.pairing(g,g).powZn((a.mul(r).mul(rho).mul(u).mul(s)));
        CTout CTout = new CTout();
        CTout.setC0(ct.getC0());
        CTout.setL1(L1);
        CTout.setV1(V1);
        CTout.setCm(ct.getCm());
        return CTout;
    }


    public byte[] Dec(CTout CTout, SK sk){
        Element C0 = CTout.getC0();
        Element L1 = CTout.getL1();
        Element V1 = CTout.getV1();
        byte[] CM = CTout.getCm();
        Element D4 = sk.getD4();
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

    public boolean KeySanityCheck(SK sk){
        Element D1 = sk.getD1().getImmutable();
        Element D2 = sk.getD2().getImmutable();
        D3_Map[] D3 = sk.getD3();
        Element D4 = sk.getD4().getImmutable();
        Element s_1 = sk.getS_1().getImmutable();
        Element s_11 = sk.getS_11().getImmutable();
        Element u_1 = sk.getU_1().getImmutable();
        Element u_11 = sk.getU_11().getImmutable();
        Element u_111 = sk.getU_111().getImmutable();
        int k_t = D3.length;
        Element sum = G1.newElement().setToOne().getImmutable();
        Element sum1 = G1.newElement().setToOne().getImmutable();
        Element k = Zr.newElement(k_t).getImmutable();
        for (int i = 0; i < k_t; i++) {
            String attributes_md5 = DigestUtils.md5DigestAsHex(D3[i].getAttr().getBytes());
            Element xi = Zr.newElementFromHash(attributes_md5.getBytes(),0,attributes_md5.length()).getImmutable();
            sum = sum.mul(D3[i].getD3().powZn(xi));
            sum1 = sum1.mul(D3[i].getD3());
        }
        Element e1 = pairing.pairing(D1,(h.mul(g.powZn(D2)))).powZn(k);
        Element e2 = pairing.pairing(g,sum);
        Element e3 = pairing.pairing(f,sum1);
        Element left = e1.mul(e2).mul(e3);
        Element right = Y.powZn(k);
        if(left.equals(right)){
            return true;
        }
        return false;
    }

    public String Trace(MSK msk, SK sk){
        Element k1 = msk.getK1();
        Element k2 = msk.getK2();
        String delta = sk.getDelta_s();
        Element theta = sk.getTheta();
        byte[] delta_2 = Base64.getDecoder().decode(delta);
        byte[] delta_m = Crytpto.SDec(delta_2, k2.toBytes());
        String theta_s = new String(delta_m);
        String zeta = theta_s.replace(theta.toString(),"");
        byte[] decoded = Base64.getDecoder().decode(zeta);
        byte[] id_t = Crytpto.SDec(decoded,k1.toBytes());
        String id_revo = new String(id_t);
        if(id_revo != null){
            return id_revo;
        }else{
            return null;
        }

    }
}

