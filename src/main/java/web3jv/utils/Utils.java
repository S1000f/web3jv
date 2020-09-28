package web3jv.utils;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * <p>단위변환, 타입 변환 등의 공용 유틸리티의 모음. 전역 메소드로만 구성됨.</p>
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public class Utils {

    /*
    * util class not allowed to be instantiated
    * */
    private Utils() {}

    public static BigDecimal fromWeiBigDecimal(BigDecimal amount, UnitProvider targetUnit) {
        BigDecimal position = new BigDecimal("10").pow(targetUnit.getWeiValue());
        amount = amount.divide(position, targetUnit.getWeiValue(), RoundingMode.CEILING);

        return amount;
    }

    public static String fromWeiString(BigDecimal amount, UnitProvider targetUnit) {
        return fromWeiBigDecimal(amount, targetUnit).toString();
    }

    public static String fromWeiString(String amount, UnitProvider targetUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return fromWeiString(converted, targetUnit);
    }

    public static BigDecimal toWeiBigDecimal(BigDecimal amount, UnitProvider originUnit) {
        BigDecimal position = new BigDecimal("10").pow(originUnit.getWeiValue());
        amount = amount.multiply(position).stripTrailingZeros();

        return amount;
    }

    public static BigDecimal toWeiBigDecimal(String amount, UnitProvider originUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return toWeiBigDecimal(converted, originUnit);
    }

    public static String toWeiString(BigDecimal amount, UnitProvider originUnit) {
        BigDecimal result = toWeiBigDecimal(amount, originUnit);
        return result.toPlainString();
    }

    public static String toWeiString(String amount, UnitProvider originUnit) {
        BigDecimal converted = new BigDecimal(amount);
        return toWeiString(converted, originUnit);
    }

    public static String toHexStringNo0x(byte[] input) {
        return Hex.toHexString(input);
    }

    public static String toHexStringNo0x(String number, int radix) {
        return toHexStringNo0x(new BigInteger(number, radix).toByteArray());
    }

    public static String toHexStringNo0x(int decimal) {
        return toHexStringNo0x(String.valueOf(decimal), 10);
    }

    public static String toHexStringNo0x(String plainText, Charset charset) {
        Charset encoded = charset == null ? StandardCharsets.UTF_8 : charset;
        return toHexStringNo0x(plainText.getBytes(encoded));
    }

    public static byte[] toBytes(String hexStringNo0x) {
        return ByteUtils.fromHexString(hexStringNo0x);
    }

    /**
     * <p>이더리움 주소를 라이브러리 내부 작업에 쉽게 사용할 수 있도록 노말라이징한다.
     * '0x' 접두어가 있다면 삭제하고, EIP-55 checksum 이 적용되어 있다면 모두 소문자로 치환한다. </p>
     * @param address 이더리움 주소
     * @return '0x' 와 EIP55 체크섬이 없는 이더리움 주소
     */
    public static String generifyAddress(String address) {
        return address.toLowerCase().startsWith("0x") ? address.toLowerCase().substring(2) : address.toLowerCase();
    }

    public static byte[] concatBytes(List<byte[]> list) {
        int totalLength = list.stream()
                .map(b -> b.length)
                .reduce((pre, curr) -> pre + curr)
                .get();

        byte[] builder = new byte[totalLength];
        int filled = 0;
        for (byte[] source : list) {
            System.arraycopy(source, 0, builder, filled, source.length);
            filled += source.length;
        }

        return builder;
    }
}
