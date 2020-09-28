package web3jv.jsonrpc.abi;

import web3jv.crypto.CryptoUtils;
import web3jv.utils.UnitProvider;
import web3jv.utils.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ERC20 implements ABI {

    private String name;
    private List<String> paramsList;
    private String address;


    public String getTxDataBalanceOf(String addressFrom) {
        byte[] func = functionSelector("balanceOf", Collections.singletonList("address"));
        byte[] addressByte = getParamAddress(addressFrom);
        byte[] txDataByte = Utils.concatBytes(Arrays.asList(func, addressByte));

        return "0x" + Utils.toHexStringNo0x(txDataByte);
    }

    public String getTxDataTransfer(String addressTo, String amount, UnitProvider originUnit) {
        byte[] func = functionSelector("transfer", Arrays.asList("address", "uint256"));
        byte[] addressByte = getParamAddress(addressTo);
        byte[] amountByte = getParamAmount(amount, originUnit);
        byte[] concated = Utils.concatBytes(Arrays.asList(func, addressByte, amountByte));

        return "0x" + Utils.toHexStringNo0x(concated);
    }

    public byte[] functionSelector(String name, List<String> paramsList) {
        StringBuilder builder = new StringBuilder(name);
        builder.append("(");
        if (paramsList != null && ! paramsList.isEmpty()) {
            paramsList.forEach(p -> builder.append(p).append(","));
            builder.deleteCharAt(builder.length() - 1);
        }
        builder.append(")");

        byte[] bytes = CryptoUtils.getKeccack256Bytes(builder.toString().getBytes());
        String result = Utils.toHexStringNo0x(bytes);

        return Utils.toBytes(result.substring(0, 8));
    }

    public byte[] getZeroPaddedBytes(byte[] source, int length) {
        byte[] zeroPadded = new byte[length];
        System.arraycopy(source, 0, zeroPadded, length - source.length, source.length);

        return zeroPadded;
    }

    public byte[] getParamAddress(String address) {
         return getZeroPaddedBytes(Utils.toBytes(Utils.generifyAddress(address)), 32);
    }

    public byte[] getParamAmount(String amount, UnitProvider unitProvider) {
        String amountWeiDecimal = Utils.toWeiString(amount, unitProvider);
        byte[] source = Utils.toBytes(Utils.toHexStringNo0x(amountWeiDecimal, 10));


        return
    }






}
