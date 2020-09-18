package web3jv.jsonrpc.transaction;

import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jvProvider;

public class StubWeb3jv implements Web3jvProvider {

    private String endpoint;
    private String chainId;

    @Override
    public String getEndpoint() {
        return endpoint;
    }

    @Override
    public void setEndpoint(String endpoint, ChainId chainId) {
        this.endpoint = endpoint;
        this.chainId = chainId.toString();
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
    public void setChainId(ChainId chainId) {
        this.chainId = chainId.toString();
    }

    @Override
    public void setCustomChainId(String customChainId) {
        this.chainId = customChainId;
    }
}
