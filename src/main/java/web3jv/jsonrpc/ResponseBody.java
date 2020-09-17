package web3jv.jsonrpc;

public class ResponseBody implements ResponseInterface {

    private int id;
    private String jsonrpc;
    private String result;
    private String error;

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public String getJsonrpc() {
        return jsonrpc;
    }

    @Override
    public String getResult() {
        return result;
    }

    @Override
    public void setId(int id) {
        this.id = id;
    }

    @Override
    public void setJsonrpc(String jsonrpc) {
        this.jsonrpc = jsonrpc;
    }

    @Override
    public void setResult(String result) {
        this.result = result;
    }
}
