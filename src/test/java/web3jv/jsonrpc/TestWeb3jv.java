package web3jv.jsonrpc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.RlpEncoder;
import web3jv.jsonrpc.transaction.Transaction;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * <p>인퓨라를 통해 이더리움 네트워크와 통신하는 테스트 이므로 엔드포인트의 상태에 따라
 * 테스트가 실패 할 수도 있음에 유의.</p>
 */
public class TestWeb3jv {

    private Web3jv web3jv;
    private String samplePriKey;
    private String sampleAddressFrom;
    private String sampleAddressTo;
    private EncoderProvider encoder;

    @BeforeEach
    public void setUp() {
        web3jv = new Web3jv(
                "https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11",
                DefaultChainId.ROPSTEN
        );
        samplePriKey = "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e";
        sampleAddressFrom = "0xAAA4d18979F2d3A52c426574Ed5b444a8E496A5d";
        sampleAddressTo = "0x7b74C763119a062A52AEf110e949542f838bB660";
        encoder = new RlpEncoder();
    }

    @DisplayName("인퓨라 엔드포인트 입력시 geth 클라이언트의 특정 버전이 반환된다")
    @Test
    public void web3jClientVersionTest() throws IOException {
        web3jv.setEndpoint(
                "https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11",
                DefaultChainId.ROPSTEN
        );
        String result = web3jv.web3ClientVersion();

        assertEquals("Geth/v1.9.9-omnibus-e320ae4c-20191206/linux-amd64/go1.13.4", result);
    }

    @Test
    public void getGasLimitTest() throws IOException {
        BigInteger result = web3jv.ethEstimateGas(sampleAddressFrom);
        assertEquals(new BigInteger("21000"), result);
    }

    @Disabled(value = "처음 테스트 실행시 트랜젝션이 블록에 생성중인 상태(pending)일 경우, " +
            "테스트 재실행 시 이전 테스트의 트랜젝션과 같은 논스를 가진 트랜젝션이 생성되므로 테스트가 실패할 수 있다")
    @DisplayName("트랜젝션 해시값이 올바르게 만들어진다")
    @Test
    public void ethSendRawTransactionTest() throws IOException {
        Transaction transaction = getSampleTransaction();
        String signedTx = transaction.signRawTransaction(web3jv, samplePriKey, encoder, null);

        String txHash = transaction.generateTxHash();
        String result = web3jv.ethSendRawTransaction(signedTx);

        assertEquals(result, txHash);
    }

    private Transaction getSampleTransaction() throws IOException {
        return Transaction.builder()
                .nonce(web3jv.ethGetTransactionCount(sampleAddressFrom))
                .gasPrice(web3jv.ethGasPrice())
                .gasLimit(new BigInteger("21000"))
                .to(sampleAddressTo)
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .chainId(web3jv.getChainId())
                .build();
    }
}
