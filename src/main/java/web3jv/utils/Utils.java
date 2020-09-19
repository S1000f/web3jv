package web3jv.utils;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigDecimal;
import java.math.BigInteger;
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

    public static BigDecimal toWeiBigDecimal(BigDecimal amount, EtherUnit originUnit) {
        BigDecimal position = new BigDecimal("10").pow(originUnit.getWeiValue());
        amount = amount.multiply(position).stripTrailingZeros();

        return amount;
    }

    public static BigDecimal toWeiBigDecimal(String amount, EtherUnit originUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return toWeiBigDecimal(converted, originUnit);
    }

    public static String toWeiString(BigDecimal amount, EtherUnit originUnit) {
        BigDecimal result = toWeiBigDecimal(amount, originUnit);
        return result.toPlainString();
    }

    public static String toWeiString(String amount, EtherUnit originUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return toWeiString(converted, originUnit);
    }

    public static String toHexStringNo0x(String decimal) {
        return Hex.toHexString(new BigInteger(decimal, 16).toByteArray());
    }

    public static String toHexStringNo0x(int decimal) {
        return toHexStringNo0x(String.valueOf(decimal));
    }
}
