package web3jv.jsonrpc;

public interface ResponseInterface {
    int getId();
    String getJsonrpc();
    String getResult();
    void setId(int id);
    void setJsonrpc(String jsonrpc);
    void setResult(String result);
}
