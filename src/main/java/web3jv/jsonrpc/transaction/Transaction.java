package web3jv.jsonrpc.transaction;

import net.consensys.cava.rlp.RLP;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.math.BigInteger;

public class Transaction {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private String v;
    private String r;
    private String s;
    private String chainId;
    private String from;

    public Transaction(String to) {
        this.to = to;
    }

    public Transaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            String v,
            String r,
            String s,
            String chainId,
            String from) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = to;
        this.value = value;
        this.data = data;
        this.v = chainId;
        this.r = r;
        this.s = s;
        this.chainId = chainId;
        this.from = from;
    }

    public byte[] encodeRlp() {
        return RLP.encodeList(writer -> {
            writer.writeBigInteger(this.nonce);
            writer.writeBigInteger(this.gasPrice);
            writer.writeBigInteger(this.gasLimit);
            writer.writeByteArray(ByteUtils.fromHexString(this.to));
            writer.writeBigInteger(this.value);
            writer.writeByteArray(ByteUtils.fromHexString(this.data));
            writer.writeByteArray(ByteUtils.fromHexString(this.v));
            writer.writeByteArray(ByteUtils.fromHexString(this.r));
            writer.writeByteArray(ByteUtils.fromHexString(this.s));
        }).toArray();
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String from) {
        this.from = from;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public BigInteger getGasLimit() {
        return gasLimit;
    }

    public void setGasLimit(BigInteger gasLimit) {
        this.gasLimit = gasLimit;
    }

    public BigInteger getGasPrice() {
        return gasPrice;
    }

    public void setGasPrice(BigInteger gasPrice) {
        this.gasPrice = gasPrice;
    }

    public BigInteger getValue() {
        return value;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    public String getV() {
        return v;
    }

    public void setV(String v) {
        this.v = v;
    }

    public String getR() {
        return r;
    }

    public void setR(String r) {
        this.r = r;
    }

    public String getS() {
        return s;
    }

    public void setS(String s) {
        this.s = s;
    }
}
