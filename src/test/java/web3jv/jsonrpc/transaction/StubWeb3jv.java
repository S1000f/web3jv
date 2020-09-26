package web3jv.jsonrpc.transaction;

import web3jv.jsonrpc.ChainIdProvider;
import web3jv.jsonrpc.Web3jvProvider;

// Web3jv의 스텁
public class StubWeb3jv implements Web3jvProvider {

    private String endpoint;
    private ChainIdProvider chainId;

    @Override
    public String getEndpoint() {
        return endpoint;
    }

    @Override
    public void setEndpoint(String endpoint, ChainIdProvider chainId) {
        this.endpoint = endpoint;
        this.chainId = chainId;
    }

    @Override
    public ChainIdProvider getChainId() {
        return chainId;
    }

    @Override
    public void setChainId(ChainIdProvider defaultChainId) {
        this.chainId = defaultChainId;
    }
}
