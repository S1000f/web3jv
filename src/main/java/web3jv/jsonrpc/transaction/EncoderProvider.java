package web3jv.jsonrpc.transaction;

import java.math.BigInteger;

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

}
