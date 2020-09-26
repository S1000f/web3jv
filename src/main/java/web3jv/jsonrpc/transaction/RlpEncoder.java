package web3jv.jsonrpc.transaction;

import net.consensys.cava.bytes.Bytes;
import net.consensys.cava.rlp.RLP;
import net.consensys.cava.rlp.RLPWriter;
import web3jv.utils.Utils;

import java.math.BigInteger;
import java.util.List;

/**
 * <p>RLP 인코더.</p>
 * <p>additional 필드는 이더리움 기본 클라이언트의 트랜젝션 구조에 포함되지 않는,
 * 별도의 커스텀된 트랜젝션 구성항목을 포함하여 인코딩할때 사용된다. 추가 항목이 없을
 * 경우엔 <i>null</i> 을 전달해야 한다.</p>
 * @implNote net.consensys.cava 라이브러리 사용
 * @see DecoderProvider
 * @see EncoderProvider
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public class RlpEncoder implements EncoderProvider, DecoderProvider {

    private BigInteger nonce;
    private BigInteger gasPrice;
    private BigInteger gasLimit;
    private String to;
    private BigInteger value;
    private String data;
    private String v;
    private String r;
    private String s;
    private List<byte[]> additional;

    /**
     * <p>트랜젝션 바디의 각 필드값을 RLP 인코딩 체계로 인코딩한다. 인코딩 하기 전에
     * 본 인스턴스에 인코딩될 값들을 주입해야 한다.</p>
     * @return byte[] 인코딩된 값
     * @since 0.1.0
     */
    @SuppressWarnings("Convert2MethodRef")
    public byte[] encode() {
        byte[] result;
        if (additional != null) {
            result = RLP.encodeList(writer -> {
                encodeDefault(writer);
                this.additional.forEach(a -> writer.writeByteArray(a));
            }).toArray();
        } else {
            result = RLP.encodeList(writer -> encodeDefault(writer))
                    .toArray();
        }

        return result;
    }

    private void encodeDefault(RLPWriter writer) {
        writer.writeBigInteger(this.nonce);
        writer.writeBigInteger(this.gasPrice);
        writer.writeBigInteger(this.gasLimit);
        writer.writeByteArray(Utils.toBytes(this.to));
        writer.writeBigInteger(this.value);
        writer.writeByteArray(Utils.toBytes(this.data));
        writer.writeByteArray(Utils.toBytes(this.v));
        writer.writeByteArray(Utils.toBytes(this.r));
        writer.writeByteArray(Utils.toBytes(this.s));
    }

    public Transaction decode(byte[] receivedTx) {
        Bytes wrapped = Bytes.wrap(receivedTx);
        Transaction transaction = new Transaction();

        return RLP.decodeList(wrapped, (reader) -> {
            transaction.setNonce(reader.readBigInteger());
            transaction.setGasPrice(reader.readBigInteger());
            transaction.setGasLimit(reader.readBigInteger());
            transaction.setTo(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setValue(reader.readBigInteger());
            transaction.setData(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setV(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setR(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setS(Utils.toHexStringNo0x(reader.readByteArray()));
            return transaction;
        });
    }

    public Transaction decode(String receivedTx) {
        String cut = receivedTx.startsWith("0x") ? receivedTx.substring(2) : receivedTx;
        return decode(Utils.toBytes(cut));
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

    public void setAdditional(List<byte[]> additional) {
        this.additional = additional;
    }

    @Override
    public String toString() {
        return "nonce : " + this.nonce + "\n" +
                "gasPrice : " + this.gasPrice + "\n" +
                "gasLimit : " + this.gasLimit + "\n" +
                "to : " + this.to + "\n" +
                "value : " + this.value + "\n" +
                "data : " + this.data + "\n" +
                "v : " + this.v + "\n" +
                "r : " + this.r + "\n" +
                "s : " + this.s + "\n" +
                "additional : " + this.additional;
    }
}
