package web3jv.jsonrpc.transaction;

import net.consensys.cava.rlp.RLP;
import web3jv.utils.Utils;

import java.math.BigInteger;

/**
 * <p>RLP 인코더.</p>
 * @implNote net.consensys.cava 라이브러리 사용
 * @see RlpEncoder#encode()
 * @see web3jv.jsonrpc.transaction.EncoderProvider
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
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

    /**
     * <p>트랜젝션 바디의 각 필드값을 RLP 인코딩 체계로 인코딩한다. 인코딩 하기 전에
     * 본 인스턴스에 인코딩될 값들을 주입해야 한다.</p>
     * @return byte[] 인코딩된 값
     * @since 0.1.0
     */
    public byte[] encode() {
        return RLP.encodeList(writer -> {
            writer.writeBigInteger(this.nonce);
            writer.writeBigInteger(this.gasPrice);
            writer.writeBigInteger(this.gasLimit);
            writer.writeByteArray(Utils.toBytes(this.to));
            writer.writeBigInteger(this.value);
            writer.writeByteArray(Utils.toBytes(this.data));
            writer.writeByteArray(Utils.toBytes(this.v));
            writer.writeByteArray(Utils.toBytes(this.r));
            writer.writeByteArray(Utils.toBytes(this.s));
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
