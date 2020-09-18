package web3jv.jsonrpc;

public enum ChainId {

    MAIN(1),
    ROPSTEN(3),
    RINKEBY(4),
    GOERILI(5),
    KOVAN(42),
    GETH_PRIVATE_DEFAULT(1337);

    private final int chainId;

    ChainId(int chainId) {
        this.chainId = chainId;
    }

    public int getChainId() {
        return chainId;
    }

    @Override
    public String toString() {
        return String.valueOf(chainId);
    }
}
