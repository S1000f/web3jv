package web3jv.jsonrpc;

import java.util.function.Supplier;

/**
 * <p>JSON-RPC 통신 결과로 error 메시지를 수신한 경우 발생</p>
 * @since 0.1.1
 * @author 김도협(닉)
 * @version 0.1.1
 */
public class JsonRpcErrorException extends Exception {
    public JsonRpcErrorException(String message) {
        super(message);
    }
}
