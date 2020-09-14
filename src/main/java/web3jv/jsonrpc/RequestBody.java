package web3jv.jsonrpc;

import java.util.List;

public interface RequestBody {
    void setJsonrpc(String jsonrpc);
    void setMethod(String method);
    void setParams(List<String> params);
    void setId(String id);
    String getJsonrpc();
    String getMethod();
    List<String> getParams();
    String getId();
}
