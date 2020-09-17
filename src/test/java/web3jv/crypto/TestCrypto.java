package web3jv.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.Web3jv;
import web3jv.jsonrpc.transaction.Transaction;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestCrypto {

    private Web3jv web3jv;
    private String samplePriKey;
    private Transaction transaction;

    @BeforeEach
    public void setUp() {
        web3jv = new Web3jv();
        web3jv.setEndpoint("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        samplePriKey = "ff4a5c68bd14cc1bb762274a18b3777bd049456f73c8dd0a0df0cd80bec1812f";
        transaction = Transaction.builder()
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
    }

    @Test
    public void signingThenGetRandSTest() {
        transaction.buildRawTransaction(web3jv, samplePriKey);
        String r = transaction.getR();
        String s = transaction.getS();

        assertEquals("968a9d774da252fad7ea210c61dfce1086de1cbda6ebf6087c7ef7c72542ca3f", r);
        assertEquals("10c8992826b7a9ffb4e13252e4ff04eb512c1c0965a1b32799b3126b23d44e31", s);
    }

    @Test
    public void buildRawTransactionBodyTest() throws JsonProcessingException {
        transaction.buildRawTransaction(web3jv, samplePriKey);
        transaction.setV("0bdb490f");
        String rawTxHexString = Hex.toHexString(transaction.encodeRlp());

        String answer = "0xf8703d84861c468082520894a11cb28a6066684db968075101031d3151dc40ed89" +
                "056bc75e2d6310000080840bdb490fa0968a9d774da252fad7ea210c61dfce1086de1" +
                "cbda6ebf6087c7ef7c72542ca3fa010c8992826b7a9ffb4e13252e4ff04eb512c1c0965a" +
                "1b32799b3126b23d44e31";

        assertEquals(answer, "0x" + rawTxHexString);

    }
}
