package web3jv.jsonrpc;

public interface Web3jvProvider {
    String getEndpoint();
    void setEndpoint(String endpoint, ChainIdProvider ChainId);
    ChainIdProvider getChainId();
    void setChainId(ChainIdProvider chain);
}
