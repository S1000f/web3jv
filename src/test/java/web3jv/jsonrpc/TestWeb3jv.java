package web3jv.jsonrpc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestWeb3jv {

    private Web3jv web3jv;
    private String sampleAddress1;

    /**
     * JSON-RPC 목 객체가 아직 구현전이므로,
     * 아래 엔드포인트의 상태에 따라 테스트가 실패 할 수도 있음
     */
    @BeforeEach
    public void setUp() {
        web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        sampleAddress1 = "0xa11CB28A6066684DB968075101031d3151dC40ED";
    }

    @Test
    public void web3jClientVersionTest() throws IOException {
        web3jv.setEndpoint("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11", ChainId.ROPSTEN);
        String result = web3jv.web3ClientVersion();

        assertEquals("Geth/v1.9.9-omnibus-e320ae4c-20191206/linux-amd64/go1.13.4", result);
    }

    @Test
    public void getGasLimitTest() throws IOException {
        BigInteger result = web3jv.ethEstimateGas(sampleAddress1);
        assertEquals(new BigInteger("21000"), result);
    }
}
