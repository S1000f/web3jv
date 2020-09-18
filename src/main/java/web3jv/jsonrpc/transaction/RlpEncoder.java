package web3jv.jsonrpc.transaction;

import net.consensys.cava.rlp.RLP;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.math.BigInteger;

public class RlpEncoder implements EncoderProvider {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private String v;
    private String r;
    private String s;

    public byte[] encode() {
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

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    public void setGasPrice(BigInteger gasPrice) {
        this.gasPrice = gasPrice;
    }

    public void setGasLimit(BigInteger gasLimit) {
        this.gasLimit = gasLimit;
    }

    public void setTo(String to) {
        this.to = to;
    }

    public void setValue(BigInteger value) {
        this.value = value;
    }

    public void setData(String data) {
        this.data = data;
    }

    public void setV(String v) {
        this.v = v;
    }

    public void setR(String r) {
        this.r = r;
    }

    public void setS(String s) {
        this.s = s;
    }
}
