package cn.shopping.lstsm.utils.lsss;

import java.util.Arrays;

public class LSSSShares {
    private Vector vector;
    private String[] map;

    public LSSSShares(Vector vector, String[] map){
        this.vector = vector;
        this.map = map;
    }
    public Vector getVector(){
        return this.vector;
    }

    public String toString(){
        int len = this.vector.getLen();
        String res = "{\n";
        for(int i = 0; i < len; i++){
            res += "    " + this.vector.getValue(i) + "  -- " + this.map[i] + " " + i + "\n";
        }
        res += "}";
        return res;
    }
    public String toString2(){
        int len = this.vector.getLen();
        String res = "{\n";
        for(int i = 0; i < len; i++){
            res += "    " + this.vector.getValue2(i) + "  -- " + this.map[i] + " " + i + "\n";
        }
        res += "}";
        return res;
    }

    public LSSSShares extract(String[] attrs){
        int[] res = new int[this.map.length];
        int index = 0;
        for(int i = 0; i < attrs.length; i++){
            for (int j = 0; j < this.map.length; j++) {
                if(attrs[i].equals(this.map[j])){
                    res[index++] = j;
                    break;
                }
            }
        }
        res = Arrays.copyOf(res, index);

        Vector vector = this.vector.extract(res);
        String[] map = new String[res.length];
        for(int i = 0; i < res.length; i++){
            map[i] = this.map[res[i]];
        }
        return new LSSSShares(vector, map);
    }

    public int recover(Vector lambda){
        return this.vector.transform().mul1(lambda);
    }
}
