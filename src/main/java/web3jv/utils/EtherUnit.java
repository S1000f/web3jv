package web3jv.utils;

public enum EtherUnit {

    WEI(1),
    KWEI(3),
    MWEI(6),
    GWEI(9),
    MICROETH(12),
    MILLIETHER(15),
    ETHER(18);

    private int weiValue;

    EtherUnit(int weiValue) {
        this.weiValue = weiValue;
    }

    public int getWeiValue() {
        return weiValue;
    }

    @Override
    public String toString() {
        return String.valueOf(weiValue);
    }
}
