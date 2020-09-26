package web3jv.utils;

/**
 * <p>단위변환 유틸에 사용될 자릿수 이동을 위한 상수를 정의한다. 함수형 인터페이스.</p>
 * @see EtherUnit
 * @since 0.1.0
 * @author 김도협(닉)
 * @version 0.1.0
 */
@FunctionalInterface
public interface UnitProvider {
    int getWeiValue();
}
