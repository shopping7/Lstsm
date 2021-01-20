package cn.shopping.lstsm.utils.lsss;

import java.util.Arrays;

public class LSSSMatrix {
    private Matrix matrix;
    private String[] map;
    private int[] index;


    public LSSSMatrix(String attr){
        this.matrix = Matrix.ONE;
        this.map = new String[]{attr};
    }

    public LSSSMatrix(Matrix matrix, String[] map) {
        this.matrix = matrix;
        this.map = map;
    }

    public LSSSMatrix(Matrix matrix, String[] map, int[] index) {
        this.matrix = matrix;
        this.map = map;
        this.index = index;
    }

    public Matrix getMartix(){
        return this.matrix;
    }

    public String[] getMap() {
        return map;
    }

    public int[] getIndex() {
        return index;
    }

    public void setIndex(int[] index) {
        this.index = index;
    }

    public LSSSMatrix or(LSSSMatrix p){
        Matrix a = this.matrix;
        Matrix b = p.matrix;
        int cols = a.getCols() + b.getCols() - 1;
        int rows = a.getRows() + b.getRows();

        Matrix res = new Matrix(rows, cols);
        String[] resmap = new String[rows];
        int temp;
        for(int i = 0; i < rows; i++) {
            if(i < a.getRows()){
                resmap[i] = this.map[i];
                for(int j = 0; j < a.getCols(); j++)
                    res.setValue(i, j, a.getValue(i, j));
            }else{
                temp = i - a.getRows();
                resmap[i] = p.map[temp];
                res.setValue(i, 0, b.getValue(temp, 0));
                for(int j = a.getCols(); j < cols; j++)
                    res.setValue(i, j, b.getValue(temp, j-a.getCols() + 1));
            }
        }
        return new LSSSMatrix(res, resmap);
    }

    public LSSSMatrix and(LSSSMatrix p){
        Matrix a = this.matrix;
        Matrix b = p.matrix;
        int cols = a.getCols() + b.getCols();
        int rows = a.getRows() + b.getRows();

        Matrix res = new Matrix(rows, cols);
        String[] resmap = new String[rows];
        int temp;
        for(int i = 0; i < rows; i++) {
            if(i < a.getRows()){
                resmap[i] = this.map[i];
                res.setValue(i, 0, a.getValue(i, 0));
                for(int j = 1; j <= a.getCols(); j++) {
                    res.setValue(i, j, a.getValue(i, j-1));
                }

            }else{
                temp = i - a.getRows();
                resmap[i] = p.map[temp];
                res.setValue(i, 1, b.getValue(temp, 0));
                for(int j = a.getCols()+1; j < cols; j++)
                    res.setValue(i, j, b.getValue(temp, j-a.getCols()));
            }
        }
        return new LSSSMatrix(res, resmap);
    }

    public LSSSShares genShareVector(Vector vector){
        Vector res = this.matrix.mul(vector);
        return new LSSSShares(res, this.map);
    }
    public LSSSShares genShareVector2(Vector vector){
        Vector res = this.matrix.mul2(vector);
        return new LSSSShares(res, this.map);
    }

    public LSSSMatrix extract(String[] attrs){
        int[] res = new int[attrs.length];
        int index = 0;
        for(int i = 0; i < attrs.length; i++){
            //可优化
            for (int j = 0; j < this.map.length; j++) {
                if(attrs[i].equals(this.map[j])){
                    res[index++] = j;
                    break;
                }
            }
        }
        res = Arrays.copyOf(res, index);

        Matrix matrix = this.matrix.extract(res);
        String[] map = new String[res.length];

        for(int i = 0; i < res.length; i++){
            map[i] = this.map[res[i]];
        }
        return new LSSSMatrix(matrix, map,res);
    }

    public int recover(LSSSShares shares){
        Matrix tm = this.matrix.transform();
        //System.out.println(tm);
        Vector v = new Vector(tm.getRows(), false);
        v.setValue(0, 1);
        Vector rv = tm.GaussianElimination(v);// v=(1,0,...,0);
        if(!tm.mul(rv).equals(v))
            return 0;
        int res = shares.recover(rv); //share.mul(rv)= res 即秘密s 其中rv用过高斯消元法得到
        return res;
    }
    public Vector getRv(){
        Matrix tm = this.matrix.transform();
        //System.out.println(tm);
        Vector v = new Vector(tm.getRows(), false);
        v.setValue(0, 1);
        Vector rv = tm.GaussianElimination(v);// v=(1,0,...,0);
        if(!tm.mul(rv).equals(v))
            return null;
        else return rv;

    }



    public String toString(){
        int cols = this.matrix.getCols();
        int rows = this.matrix.getRows();
        String res = "{\n";
        for(int i = 0; i < rows; i++) {
            res += "    ";
            for (int j = 0; j < cols; j++) {
                res += this.matrix.getValue(i, j) + ", ";
            }
            if (this.index != null) {
                res += "  -- " + this.map[i] + " " + this.index[i] + "\n";
            } else {
                res += "  -- " + this.map[i] + " " + i + "\n";
            }
        }
        res += "}";
        return res;
    }


}
