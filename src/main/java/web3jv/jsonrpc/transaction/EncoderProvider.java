package web3jv.jsonrpc.transaction;

import java.math.BigInteger;
import java.util.List;

/**
 * <p>트랜젝션 바디를 인코딩 하기위해 사용되는 인코더를 정의한 인터페이스.
 * 트랜젝션을 사이닝하는 메소드에 마지막 인자로 전달된다.</p>
 * <p>현재 인코딩 방식은 <i>RLP(Recursive Length Prefix)</i>이나, 훗날 변경될 가능성이
 * 있으며(<a href="https://eth.wiki/en/fundamentals/rlp">참조</a>), 이더리움 인코딩 체계가
 * 변경 되거나, 다른 RLP 라이브러리를 적용 혹은 직접 제작할 경우 본 인터페이스를 구현
 * 하여야 한다.</p>
 * <p>additional 필드는 이더리움 기본 클라이언트의 트랜젝션 구조에 포함되지 않는,
 * 별도의 커스텀된 트랜젝션 구성항목을 포함하여 인코딩할때 사용된다. 추가 항목이 없을
 * 경우엔 <i>null</i> 을 전달해야 한다.</p>
 *
 * @implSpec
 * 트랜젝션의 각 요소(<i>nonce, gasPrice, gasLimit, addressTo, value, data, v, r, s</i>)
 * 들의 setter 을 구현해야 하며, {@link EncoderProvider#encode()} 는 인코딩된 결과를 {@code byte[]}
 * 타입으로 반환하도록 구현해야 한다.
 * @see Transaction#signRawTransaction
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
public interface EncoderProvider {
    byte[] encode();
    void setNonce(BigInteger nonce);
    void setGasPrice(BigInteger gasPrice);
    void setGasLimit(BigInteger gasLimit);
    void setTo(String to);
    void setValue(BigInteger value);
    void setData(String data);
    void setV(String v);
    void setR(String r);
    void setS(String s);
    void setAdditional(List<byte[]> additional);
}
