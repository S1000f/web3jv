package web3jv.jsonrpc;

import java.util.List;

public interface RequestInterface {
    void setJsonrpc(String jsonrpc);
    void setMethod(String method);
    void setParams(List<Object> params);
    void setId(String id);
    String getJsonrpc();
    String getMethod();
    List<Object> getParams();
    String getId();
}
