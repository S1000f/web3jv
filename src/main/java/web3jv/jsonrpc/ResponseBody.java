package web3jv.jsonrpc;

import com.fasterxml.jackson.annotation.JsonAnySetter;

import java.util.Map;

public class ResponseBody implements ResponseInterface {

    private int id;
    private String jsonrpc;
    private String result;
    @JsonAnySetter
    private Map<String, String> error;

    public Map<String, String> getError() {
        return error;
    }

    public void setError(Map<String, String> error) {
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
