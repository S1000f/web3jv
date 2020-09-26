package web3jv.jsonrpc;

import web3jv.utils.Utils;

/**
 * <p>알려진 이더리움 네트워크의 체인아이디로 {@code ChainIdProvider} 를 구현한 열거형 객체.
 * 목록:
 * <pre>
 *     이더리움 메인넷: 1
 *     Ropsten 테스트넷: 3
 *     Rinkeby 테스트넷: 4
 *     Goerli 테스트넷: 5
 *     Kovan 테스트넷: 42
 *     Geth 사설네트워크 default: 1337
 * </pre></p>
 * <p>기존의 체인아이디 값이 변경되거나 별도의 체인아이디를 사용할 필요가 있을땐,
 * {@code ChainIdProvider} 를 구현하거나 람다식을 사용한다.</p>
 * @see ChainIdProvider
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public enum DefaultChainId implements ChainIdProvider {

    MAIN(1),
    ROPSTEN(3),
    RINKEBY(4),
    GOERILI(5),
    KOVAN(42),
    GETH_PRIVATE_DEFAULT(1337);

    private final int chainId;

    DefaultChainId(int chainId) {
        this.chainId = chainId;
    }

    /**
     * 체인아이디의 int 값을 반환한다.
     * @return int 체인아이디
     */
    public int toInt() {
        return chainId;
    }

    /**
     * 체인아이디의 16진수 hex String 을 반환한다.
     * @return '0x' 없는 hex String
     */
    public String toHexStringNo0x() {
        return Utils.toHexStringNo0x(chainId);
    }

    /**
     * 체인아이디의 10진수 String 을 반환한다.
     * @return 10진수 String
     */
    @Override
    public String toString() {
        return String.valueOf(chainId);
    }
}
