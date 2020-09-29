package web3jv.jsonrpc;

import java.util.Map;

public interface ResponseInterface {
    int getId();
    String getJsonrpc();
    String getResult();
    void setId(int id);
    void setJsonrpc(String jsonrpc);
    void setResult(String result);
    public Map<String, String> getError();
    public void setError(Map<String, String> error);
}
