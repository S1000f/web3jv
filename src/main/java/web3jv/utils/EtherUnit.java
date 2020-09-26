package web3jv.utils;

import java.math.BigDecimal;

/**
 * <p>이더리움 표준 단위변환 유틸을 위한 열거형 상수. {@code int} 상수로 구성되어 있다.
 * 표준 단위가 변경되거나 추가될 경우, {@code UnitProvider} 를 구현하거나 람다식을 이용한다.</p>
 * @see UnitProvider
 * @see Utils#fromWeiString(BigDecimal, UnitProvider)
 * @see Utils#toWeiBigDecimal(BigDecimal, UnitProvider)
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public enum EtherUnit implements UnitProvider {

    WEI(1),
    KWEI(3),
    MWEI(6),
    GWEI(9),
    MICROETH(12),
    MILLIETHER(15),
    ETHER(18);

    private final int weiValue;

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
