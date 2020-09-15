package web3jv.utils;

import java.math.BigDecimal;
import java.math.RoundingMode;

public class Utils {


//    public static String fromWei(String amount, EtherUnit targetUnit) {
//        StringBuilder builder = new StringBuilder(amount);
//        int pos = targetUnit.getWeiValue();
//        int offset = amount.length() - pos;
//        if (offset > 0) {
//            builder.insert(offset, '.');
//        } else {
//            for (int i = 0; i < offset * -1; i++) {
//                builder.insert(0, '0');
//            }
//            builder.insert(0, "0.");
//        }
//
//        return builder.toString();
//    }

    public static String fromWei(String amount, EtherUnit targetUnit) {
        BigDecimal asd = new BigDecimal(amount);
        System.out.println(asd.toString());

        BigDecimal d = new BigDecimal("10").pow(targetUnit.getWeiValue());
        System.out.println(d.toString());

        asd = asd.divide(d, targetUnit.getWeiValue(), RoundingMode.CEILING);

        return asd.toString();
    }

//    public static String toWei(String amount, EtherUnit inputUnit) {
//        StringBuilder builder = new StringBuilder(amount);
//        int pos = inputUnit.getWeiValue();
//        int dotIndex = amount.indexOf(".");
//        int lengthAfterDot = amount.length() - (dotIndex + 1);
//        int offset = pos - lengthAfterDot;
//        if (offset > 0) {
//            for (int i = 0; i < offset; i++) {
//                builder.append("0");
//            }
//        } else if (offset < 0) {
//            builder.insert(dotIndex + (offset * -1) + 1, ".");
//        }
////        if (dotIndex != null) {
////            builder.deleteCharAt(dotIndex);
////            String balance = builder.toString();
////            while (balance.startsWith("0")) {
////                balance = balance.substring(1);
////            }
////
////        }
//
////        return balance;
//    }

}
