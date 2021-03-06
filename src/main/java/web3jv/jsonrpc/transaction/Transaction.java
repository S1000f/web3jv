package web3jv.jsonrpc.transaction;

import org.bouncycastle.util.encoders.Hex;
import web3jv.crypto.CryptoUtils;
import web3jv.jsonrpc.ChainIdProvider;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.utils.Utils;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

/**
 * <p>트랜젝션 전송을 위한 트랜젝션 바디 객체. 트랜젝션 전송과정:
 * <pre>
 *     1. 트랜젝션 인스턴스 생성
 *     2. 트랜젝션 필드값 주입
 *     3. 서명
 *     4. 사인된 트랜젝션을 파라미터로 json-rpc 호출
 * </pre>
 * 인스턴스 생성 및 초기화 방식:
 * <pre>
 *     1. 생성자함수
 *     2. 빌더패턴
 * </pre></p>
 * @see Transaction#signRawTransaction
 * @see Transaction#builder()
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
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
    private ChainIdProvider chainId;
    private String from;
    private byte[] signedTx;

    public Transaction() {
    }

    /**
     * @apiNote eth_getEstimateGas 호출을 위해서만 사용할 것
     * @param to '0x' 없는 hex String
     * @since 0.1.0
     */
    public Transaction(String to) {
        this.to = to;
    }

    /**
     * <p>트랜젝션 인스턴스를 생성하고 초기화 한다. 빌더패턴을 사용할 수 도 있다.
     * @param nonce BigInteger 논스
     * @param gasPrice BigInteger 가스가격
     * @param gasLimit BigInteger 가스리미트
     * @param to String('0x' 없는 hex String) 수신주소(토큰일 경우 컨트랙트 주소)
     * @param value BigInteger 수량
     * @param data String 데이터(공백일 경우 "" 입력)
     * @param chainId 체인 식별자(사이닝 전 v 필드에 대입됨)
     * @see Transaction#builder()
     * @since 0.1.0
     */
    public Transaction(
            BigInteger nonce,
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            BigInteger value,
            String data,
            ChainIdProvider chainId
    ) {
        this.nonce = nonce;
        this.gasPrice = gasPrice;
        this.gasLimit = gasLimit;
        this.to = Utils.generifyAddress(to);
        this.value = value;
        this.data = data == null ? "" : data;
        this.chainId = chainId;
    }

    /**
     * 트랜젝션 바디를 사이닝한다.
     * <p>additional 매개변수는 이더리움 기본 클라이언트의 트랜젝션 구조에 포함되지 않는,
     * 별도의 커스텀된 트랜젝션 구성항목을 포함하여 인코딩할때 사용된다. 추가 항목이 없을
     * 경우엔 <i>null</i> 을 전달해야 한다.</p>
     * @param web3jv {@link Web3jvProvider}을 구현한 'json-rpc' wrapper 객체의 인스턴스
     * @param privateKey String 전송자의 개인키
     * @param encoder {@link EncoderProvider}을 구현한 인코더
     * @param additional 추가 항목. 해당되지 않을 경우 null 전달할 것
     * @return String '0x'를 포함한 인코딩된 hex String
     * @see Web3jvProvider
     * @see EncoderProvider
     * @since 0.1.0
     */
    public String signRawTransaction(
            Web3jvProvider web3jv,
            String privateKey,
            EncoderProvider encoder,
            List<byte[]> additional
    ) {
        setUpEncoder(encoder, additional);
        encoder.setV(this.chainId.toHexStringNo0x());
        encoder.setR("");
        encoder.setS("");
        byte[] messageHash = CryptoUtils.getKeccack256Bytes(encoder.encode());

        BigInteger[] sigs = CryptoUtils.signMessageByECDSA(encoder.encode(), privateKey);
        BigInteger r = sigs[0], s = sigs[1];

        int recId = CryptoUtils.getEIP155v(messageHash, privateKey, r, s);
        String v = Integer.toHexString(recId + (Integer.parseInt(web3jv.getChainId().toHexStringNo0x()) * 2) + 35);
        byte[] rBytes = r.toByteArray();
        String stringR = rBytes.length == 32 ? Hex.toHexString(rBytes) : Hex.toHexString(rBytes).substring(2);
        String stringS = Hex.toHexString(s.toByteArray());
        this.v = v;
        this.r = stringR;
        this.s = stringS;

        setUpEncoder(encoder, additional);
        encoder.setV(v);
        encoder.setR(stringR);
        encoder.setS(stringS);

        this.signedTx = encoder.encode();

        return "0x" + Utils.toHexStringNo0x(this.signedTx);
    }

    public String generateTxHash() {
        return "0x" + CryptoUtils.getKeccack256HexString(this.signedTx);
    }

    private void setUpEncoder(EncoderProvider encoder, List<byte[]> additional) {
        encoder.setNonce(this.nonce);
        encoder.setGasPrice(this.gasPrice);
        encoder.setGasLimit(this.gasLimit);
        encoder.setTo(this.to);
        encoder.setValue(this.value);
        encoder.setData(Optional.ofNullable(this.data).orElse(""));
        encoder.setAdditional(additional);
    }

    /**
     * <p>생성자함수 대신 빌더 패턴으로 인스턴스 생성. String 타입 매개변수명에
     * 'No0x' 가 있을경우 '0x'가 없는 hex String 을 전달할 것.</p>
     * @return Builder
     * @since 0.1.0
     */
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Transaction build = new Transaction();

        public Builder nonce(BigInteger nonce) {
            build.nonce = nonce;
            return this;
        }

        public Builder gasPrice(BigInteger gasPrice) {
            build.gasPrice = gasPrice;
            return this;
        }

        public Builder gasLimit(BigInteger gasLimit) {
            build.gasLimit = gasLimit;
            return this;
        }

        public Builder to(String hexStringNo0x) {
            build.to = Utils.generifyAddress(hexStringNo0x);
            return this;
        }

        public Builder value(BigInteger value) {
            build.value = value;
            return this;
        }

        public Builder data(String hexStringNo0x) {
            build.data = hexStringNo0x == null ? "" : hexStringNo0x;
            return this;
        }

        public Builder chainId(ChainIdProvider chainId) {
            build.chainId = chainId;
            return this;
        }

        public Builder from(String hexStringNo0x) {
            build.from = Utils.generifyAddress(hexStringNo0x);
            return this;
        }

        public Transaction build() {
            return build;
        }
    }

    public String getFrom() {
        return from;
    }

    public void setFrom(String hexStringNo0x) {
        this.from = hexStringNo0x;
    }

    public String getTo() {
        return to;
    }

    public void setTo(String hexStringNo0x) {
        this.to = hexStringNo0x;
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

    public void setData(String hexStringNo0x) {
        this.data = hexStringNo0x == null ? "" : hexStringNo0x;
    }

    public BigInteger getNonce() {
        return nonce;
    }

    public void setNonce(BigInteger nonce) {
        this.nonce = nonce;
    }

    public ChainIdProvider getChainId() {
        return chainId;
    }

    public void setChainId(ChainIdProvider chainId) {
        this.chainId = chainId;
    }

    public String getV() {
        return v;
    }

    public void setV(String hexStringNo0x) {
        this.v = hexStringNo0x;
    }

    public String getR() {
        return r;
    }

    public void setR(String hexStringNo0x) {
        this.r = hexStringNo0x;
    }

    public String getS() {
        return s;
    }

    public void setS(String hexStringNo0x) {
        this.s = hexStringNo0x;
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
                "s : " + this.s;
    }

    @Override
    public int hashCode() {
        int result = this.nonce.hashCode();
        result = 31 * result + this.gasPrice.hashCode();
        result = 31 * result + this.gasLimit.hashCode();
        result = 31 * result + Utils.generifyAddress(this.to).hashCode();
        result = 31 * result + Optional.ofNullable(this.value).orElse(BigInteger.ZERO).hashCode();
        result = 31 * result + Optional.ofNullable(this.data).orElse("").hashCode();
        result = 31 * result + this.v.hashCode();
        result = 31 * result + this.r.hashCode();
        result = 31 * result + this.s.hashCode();

        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Transaction) {
            return this.hashCode() == obj.hashCode();
        }
        return false;
    }
}
