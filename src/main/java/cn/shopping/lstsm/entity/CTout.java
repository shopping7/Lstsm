package cn.shopping.lstsm.entity;

import lombok.Data;

import it.unisa.dia.gas.jpbc.Element;

@Data
public class CTout {
    private Element C0;
    private Element L1;
    private Element V1;
    private byte[] Cm;
}
