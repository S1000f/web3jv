package web3jv.jsonrpc.transaction;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jvProvider;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestTransaction {

    private Web3jvProvider web3jv;
    private String samplePriKey;
    private EncoderProvider encoderProvider;

    @BeforeEach
    public void setUp() {
        web3jv = new StubWeb3jv();
        web3jv.setChainId(ChainId.ROPSTEN);
        encoderProvider = new RlpEncoder();
    }

    @DisplayName("ECDSA로 트랜젝션 암호화 후 r, s값을 얻는다")
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
                .v("05eda476")
                .r("")
                .s("")
                .build();

        transaction.signRawTransaction(web3jv, samplePriKey, encoderProvider);
        String r = transaction.getR();
        String s = transaction.getS();

        assertEquals("968a9d774da252fad7ea210c61dfce1086de1cbda6ebf6087c7ef7c72542ca3f", r);
        assertEquals("10c8992826b7a9ffb4e13252e4ff04eb512c1c0965a1b32799b3126b23d44e31", s);
    }

    @DisplayName("ECDSA암호화 후 v,r,s를 포함하여 RLP인코딩 값을 얻는다")
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
                .v(Utils.toHexStringNo0x(web3jv.getChainId()))
                .r("")
                .s("")
                .build();

        String rawTx = transaction.signRawTransaction(web3jv, samplePriKey, encoderProvider);

        assertEquals("0xf86a0184ee6b280082520894a11cb28a6066684db968075101031d3151dc40ed872386f" +
                "26fc10000802aa0efe1183eadf2c3ee097e80d7e2e51a32f2072cdc34bc1567b43120b6834e5112a05" +
                "e49b9c0b2851a63e6bb65e67a8e79846250a8a4a878990ba72c86649a7fe9db", rawTx);
    }
}
