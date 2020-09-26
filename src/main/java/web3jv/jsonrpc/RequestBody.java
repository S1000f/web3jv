package web3jv.jsonrpc;

import java.util.List;

public class RequestBody implements RequestInterface {

    private String jsonrpc;
    private String method;
    private List<Object> params;
    private String id;

    public RequestBody(String jsonrpc, String method, List<Object> params, String id) {
        this.jsonrpc = jsonrpc;
        this.method = method;
        this.params = params;
        this.id = id;
    }

    @Override
    public void setJsonrpc(String jsonrpc) {
        this.jsonrpc = jsonrpc;
    }

    @Override
    public void setMethod(String method) {
        this.method = method;
    }

    @Override
    public void setParams(List<Object> params) {
        this.params = params;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getJsonrpc() {
        return jsonrpc;
    }

    @Override
    public String getMethod() {
        return method;
    }

    @Override
    public List<Object> getParams() {
        return params;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String toString() {
        return "jsonrpc : " + this.jsonrpc + "\n" +
                "method : " + this.method + "\n" +
                "params : " + this.params + "\n" +
                "id : " + this.id;
    }
}
