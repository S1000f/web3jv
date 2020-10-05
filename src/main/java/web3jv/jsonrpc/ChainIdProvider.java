package web3jv.jsonrpc;

/**
 * <p>네트워크 체인아이디의 값을 확장할 수 있도록 정의한 함수형 인터페이스.
 * 구현체는 반드시 접두어 '0x' 가 없는 Hex String 을 반환하도록 한다.</p>
 * @see DefaultChainId
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
@FunctionalInterface
public interface ChainIdProvider {
    String toHexStringNo0x();
}
