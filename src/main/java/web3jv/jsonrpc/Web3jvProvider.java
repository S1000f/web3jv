package web3jv.jsonrpc;

public interface Web3jvProvider {
    String getEndpoint();
    void setEndpoint(String endpoint, ChainIdProvider defaultChainId);
    void setEndpoint(String endpoint, String customChainId);
    String getChainId();
    void setChainId(ChainIdProvider chain);
    void setCustomChainId(String customChainId);
}
