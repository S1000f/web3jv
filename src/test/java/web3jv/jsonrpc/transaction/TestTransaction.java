package web3jv.jsonrpc.transaction;

import net.consensys.cava.rlp.RLP;
import net.consensys.cava.rlp.RLPWriter;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.DefaultChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static web3jv.utils.Utils.toHexStringNo0x;

public class TestTransaction {

    private Web3jvProvider web3jv;
    private String samplePriKey;
    private EncoderProvider encoder;

    @BeforeEach
    public void setUp() {
        web3jv = new StubWeb3jv();
        web3jv.setChainId(DefaultChainId.ROPSTEN);
        encoder = new RlpEncoder();

    }

    @DisplayName("ECDSA로 트랜젝션 서명 후 r, s값을 얻는다")
    @Test
    public void signingThenGetRandSTest() {
        samplePriKey = "ff4a5c68bd14cc1bb762274a18b3777bd049456f73c8dd0a0df0cd80bec1812f";
        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("61"))
                .gasPrice(new BigInteger("861c4680", 16))
                .gasLimit(new BigInteger("5208", 16))
                .to("a11cb28a6066684db968075101031d3151dc40ed")
                .value(new BigInteger("056bc75e2d63100000", 16))
                .data("")
                .chainId("05eda476")
                .build();
        transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
        String r = transaction.getR();
        String s = transaction.getS();

        assertEquals("968a9d774da252fad7ea210c61dfce1086de1cbda6ebf6087c7ef7c72542ca3f", r);
        assertEquals("10c8992826b7a9ffb4e13252e4ff04eb512c1c0965a1b32799b3126b23d44e31", s);
    }

    @DisplayName("ECDSA 서명 후 v,r,s를 포함하여 RLP인코딩 값을 얻는다")
    @Test
    public void signingTransactionThenGetHexParam() {
        samplePriKey = "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e";
        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("1"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(new BigInteger("21000"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .data("")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .chainId(toHexStringNo0x(web3jv.getChainId()))
                .build();

        String rawTx = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        assertEquals("0xf86a0184ee6b280082520894a11cb28a6066684db968075101031d3151dc40ed872386f" +
                "26fc10000802aa0efe1183eadf2c3ee097e80d7e2e51a32f2072cdc34bc1567b43120b6834e5112a05" +
                "e49b9c0b2851a63e6bb65e67a8e79846250a8a4a878990ba72c86649a7fe9db", rawTx);
    }

    @DisplayName("트랜젝션 바디 생성시 data 를 초기화 하지 않아도 사이닝이 완료된다")
    @Test
    public void signingTransactionOptionalTest() {
        Transaction transaction = getSampleTransaction();
        String rawTx = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        assertEquals("0xf86a0184ee6b280082520894a11cb28a6066684db968075101031d3151dc40ed872386f" +
                "26fc10000802aa0efe1183eadf2c3ee097e80d7e2e51a32f2072cdc34bc1567b43120b6834e5112a05" +
                "e49b9c0b2851a63e6bb65e67a8e79846250a8a4a878990ba72c86649a7fe9db", rawTx);
    }

    @DisplayName("트랜젝션 추가 요소를 리스트 형태로 전달하여 인코딩 한다")
    @Test
    public void addAdditionalElementsToTransactionThenEncodingOkTest() {
        byte[] b1 = {1, 2};
        byte[] b2 = {3, 4};
        List<byte[]> list = Arrays.asList(b1, b2);
        byte[] tx = RLP.encodeList(writer -> {
            encodeDefault(writer);
            list.forEach(b -> writer.writeByteArray(b));
        }).toArray();

        byte[] result = RLP.encodeList(writer -> {
            encodeDefault(writer);
            writer.writeByteArray(b1);
            writer.writeByteArray(b2);
        }).toArray();

        assertEquals(Hex.toHexString(tx), Hex.toHexString(result));
    }

    @DisplayName("동일한 트랜젝션을 RLP 로 인코딩 후 다시 RLP 로 디코딩하면 값이 같다")
    @Test
    public void getTxThenDecodeItIntoTransactionObjectTest() {
        Transaction transaction = getSampleTransaction();
        String receivedTx = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        byte[] byteTx = Utils.toBytes(receivedTx.substring(2));
        DecoderProvider decoderProvider = new RlpDecoder();
        Transaction decodedTx = decoderProvider.decode(byteTx);

        assertEquals(transaction, decodedTx);
    }

    @DisplayName("동일한 인스턴스일 경우 signRawTransaction 메소드를 여러번 수행해도 결과값은 불변하다")
    @Test
    public void doSigningWithTheSameInstanceReturnImmutableResultTest() {
        Transaction transaction = getSampleTransaction();
        String signedTx1 = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
        String signedTx2 = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        assertEquals(signedTx1, signedTx2);
    }

    @DisplayName("동일한 인스턴스일 경우 txHash 을 여러번 얻어도 값이 불변하다")
    @Test
    public void getTransactionHashTest() {
        Transaction transaction = getSampleTransaction();
        transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        String txHash1 = transaction.generateTxHash();
        String txHash2 = transaction.generateTxHash();

        assertEquals(txHash1, txHash2);
    }

    @DisplayName("사이닝 메소드와 트랜젝션 해시를 얻는 메소드가 서로 영향을 주고받지 않는다")
    @Test
    public void signMethodAndTxHashMethodReturnImmutableResultsTest() {
        Transaction transaction = getSampleTransaction();
        String signedTx1 = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);
        transaction.generateTxHash();
        String signedTx2 = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        Transaction transaction2 = getSampleTransaction();
        transaction2.signRawTransaction(web3jv, samplePriKey, encoder, null);
        String txHash1 = transaction2.generateTxHash();
        transaction2.signRawTransaction(web3jv, samplePriKey, encoder, null);
        String txHash2 = transaction2.generateTxHash();

        assertEquals(signedTx1, signedTx2);
        assertEquals(txHash1, txHash2);
    }

    private Transaction getSampleTransaction() {
        samplePriKey = "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e";
        return Transaction.builder()
                .nonce(new BigInteger("1"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(new BigInteger("21000"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .chainId(toHexStringNo0x(web3jv.getChainId()))
                .build();
    }

    private void encodeDefault(RLPWriter writer) {
        writer.writeBigInteger(new BigInteger("1"));
        writer.writeBigInteger(new BigInteger("4000000000"));
        writer.writeBigInteger(new BigInteger("21000"));
        writer.writeByteArray(Utils.toBytes("a11CB28A6066684DB968075101031d3151dC40ED"));
        writer.writeBigInteger(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger());
        writer.writeByteArray(Utils.toBytes(""));
        writer.writeByteArray(Utils.toBytes(toHexStringNo0x(web3jv.getChainId())));
        writer.writeByteArray(Utils.toBytes(""));
        writer.writeByteArray(Utils.toBytes(""));
    }
}
