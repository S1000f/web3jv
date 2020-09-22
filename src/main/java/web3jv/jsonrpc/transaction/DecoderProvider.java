package web3jv.jsonrpc.transaction;

/**>
 * <p>트랜젝션 바디를 디코딩하는 디코더 모듈을 정의한 인터페이스.
 * </p>
 * @see EncoderProvider
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public interface DecoderProvider {
    Transaction decode(byte[] tx);
    Transaction decode(String tx);
}
