package web3jv.utils;

import java.math.BigDecimal;
import java.util.function.IntSupplier;

/**
 * <p>이더리움 표준 단위변환 유틸을 위한 열거형 상수. {@code int} 상수로 구성되어 있다.
 * 표준 단위가 변경되거나 추가될 경우, {@code IntSupplier} 를 구현하거나 람다식을 이용한다.</p>
 * @see Utils#fromWeiString(BigDecimal, IntSupplier)
 * @see Utils#toWeiBigDecimal(BigDecimal, IntSupplier)
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public enum EtherUnit implements IntSupplier {

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

    public int getAsInt() {
        return weiValue;
    }



}
