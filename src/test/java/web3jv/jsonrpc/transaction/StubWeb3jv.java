package web3jv.jsonrpc.transaction;

import web3jv.jsonrpc.ChainIdProvider;
import web3jv.jsonrpc.Web3jvProvider;

// Web3jv의 스텁
public class StubWeb3jv implements Web3jvProvider {

    private String endpoint;
    private String chainId;

    @Override
    public String getEndpoint() {
        return endpoint;
    }

    @Override
    public void setEndpoint(String endpoint, ChainIdProvider defaultChainId) {
        this.endpoint = endpoint;
        this.chainId = defaultChainId.toString();
    }

    @Override
    public void setEndpoint(String endpoint, String customChainId) {
        this.endpoint = endpoint;
        this.chainId = customChainId;
    }

    @Override
    public String getChainId() {
        return chainId;
    }

    @Override
    public void setChainId(ChainIdProvider defaultChainId) {
        this.chainId = defaultChainId.toString();
    }

    @Override
    public void setCustomChainId(String customChainId) {
        this.chainId = customChainId;
    }
}
