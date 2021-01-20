package cn.shopping.lstsm.utils.lsss;

import it.unisa.dia.gas.jpbc.Element;

public class Vector {
    // true - row vector; false - col vector
    private boolean flag;
    private int len;
    private int[] vector;
    private Element[] vector2;
    private String type;
    //private Field Zr;

    public Vector(int len, boolean flag){
        this.len = len;
        this.flag = flag;
        this.vector = new int[len];
    }

    public Vector(int len, boolean flag, String type){
        this.len = len;
        this.flag = flag;
        this.vector2 = new Element[len];
    }

    public Vector(boolean flag, int[] vector){
        this.len = vector.length;
        this.flag = flag;
        this.vector = vector;
    }

    public Vector(boolean flag, Element[] vector2){
        this.len = vector2.length;
        this.flag = flag;
        this.vector2 = vector2;
    }

   /* public void setZr(Field zr) {
        this.Zr = zr;
    }

    public Field getZr() {
        return Zr;
    }*/

    public Vector(int len){
        this(len, true);
    }

    public int getValue(int i){
        return this.vector[i];
    }

    public Element getValue2(int i){
        return this.vector2[i];
    }

    public void setValue(int i, int value){
        this.vector[i] = value;
    }
    public void setValue(int i, Element value){
        this.vector2[i] = value;
    }

    public boolean isFlag() {
        return flag;
    }

    public int getLen() {
        return len;
    }

    public Vector transform(){          //转秩 行向量变为列向量
        Vector res = new Vector(this.len, !this.flag);
        for(int i = 0; i < this.len; i++)
            res.vector[i] = this.vector[i];
        return res;
    }

    public Vector add(Vector a){                             //向量相加
        if(this.flag != a.flag || this.len != a.len)        //判断能否相加
            return null;
        Vector res = new Vector(this.len, this.flag);
        for(int i = 0; i < this.len; i++)
            res.vector[i] = this.vector[i]+(a.vector[i]);
        return res;

    }

    public Vector sub(Vector a){                //向量相减
        if(this.flag != a.flag || this.len != a.len)
            return null;
        Vector res = new Vector(this.len, this.flag);
        for(int i = 0; i < this.len; i++)
            res.vector[i] = this.vector[i]-(a.vector[i]);
        return res;
    }

    public Vector mul(Matrix a){        //向量乘矩阵
        if(this.len != a.getRows() || !this.flag)   //必须是行向量，且长度等于矩阵的行数，返回行向量
            return null;
        Vector res = new Vector(a.getCols(), this.flag);// flag = true
        int temp;
        for(int i = 0; i < a.getCols(); i++){
            temp = 0;
            for(int j = 0; j < this.len; j++)
                temp = temp + this.vector[j]*a.getValue(j, i);
            res.vector[i] = temp;
        }
        return res;
    }

    public Matrix mul(Vector a){    //向量乘向量，向量必须列向量,输入向量必须为行向量，得到矩阵
        if(this.flag || !a.flag)    //this.flag = false  a.flag = true
            return null;
        Matrix res = new Matrix(this.len, a.len);
        for(int i = 0; i < this.len; i++){
            for(int j = 0 ; j < this.len ; j++){
                res.setValue(i, j, this.vector[i]*a.vector[j]);
            }
        }
        return res;
    }

    public int mul1(Vector a){     //this.flag = true, a.flag = false  return int数
        if(!this.flag || a.flag || this.len != a.len)
            return 0;
        int res = 0;
        for(int i = 0; i < this.len; i++)
                res += this.vector[i] * a.vector[i];
        return res;
    }

    public Vector extract(int[] indexes) {  //indexs =(3,2,1) 提取向量第3，第2和第1个元素组成新的向量
        Vector res = new Vector(indexes.length, this.flag);
        for(int i = 0; i < indexes.length; i++){
            res.setValue(i, this.getValue(indexes[i]));
        }
        return res;
    }

    public String toString(){
        int len = this.getLen();
        String res = "{";
        for(int i = 0; i < len; i++){
            res += " " + this.getValue(i) + ", ";
        }
        res += "} -- " + this.isFlag();
        return res;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj == null)
            return false;
        if(this == obj)
            return true;
        if(! (obj instanceof Vector))
            return false;
        if(((Vector)obj).isFlag() != this.isFlag())
            return false;
        if(((Vector)obj).len != this.len)
            return false;
        if(((Vector)obj).vector == this.vector)
            return true;
        if(((Vector)obj).vector == null)
            return false;
        for(int i = 0; i < this.len; i++){
            if(((Vector)obj).vector[i] != this.vector[i])
                return false;
        }
        return true;
    }
}
