package web3jv.utils;

import java.math.BigDecimal;
import java.math.RoundingMode;

public class Utils {

    public static String fromWei(BigDecimal amount, EtherUnit targetUnit) {
        BigDecimal position = new BigDecimal("10").pow(targetUnit.getWeiValue());
        amount = amount.divide(position, targetUnit.getWeiValue(), RoundingMode.CEILING);

        return amount.toString();
    }

    public static String fromWei(String amount, EtherUnit targetUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return fromWei(converted, targetUnit);
    }

    public static String toWei(BigDecimal amount, EtherUnit originUnit) {
        BigDecimal position = new BigDecimal("10").pow(originUnit.getWeiValue());
        amount = amount.multiply(position).stripTrailingZeros();

        return amount.toPlainString();
    }

    public static String toWei(String amount, EtherUnit originUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return toWei(converted, originUnit);
    }
}
