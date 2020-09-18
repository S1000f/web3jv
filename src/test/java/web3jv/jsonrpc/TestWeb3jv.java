package web3jv.jsonrpc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TestWeb3jv {

    private Web3jv web3jv;
    private String sampleAddress1;

    @BeforeEach
    public void setUp() {
        web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        sampleAddress1 = "0xa11CB28A6066684DB968075101031d3151dC40ED";
    }

    @Test
    public void web3jClientVersionTest() throws IOException {
        // 테스트는 아래의 엔드포인트의 상황에 따라 실패할 수 도 있음
        web3jv.setEndpoint("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11", ChainId.ROPSTEN);
        String result = web3jv.web3ClientVersion();

        assertEquals("Geth/v1.9.9-omnibus-e320ae4c-20191206/linux-amd64/go1.13.4", result);
    }
}
