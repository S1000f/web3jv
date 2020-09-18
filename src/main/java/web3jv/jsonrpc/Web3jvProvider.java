package web3jv.jsonrpc;

public interface Web3jvProvider {
    String getEndpoint();
    void setEndpoint(String endpoint, ChainId chainId);
    void setEndpoint(String endpoint, String customChainId);
    String getChainId();
    void setChainId(ChainId chain);
    void setCustomChainId(String customChainId);
}
