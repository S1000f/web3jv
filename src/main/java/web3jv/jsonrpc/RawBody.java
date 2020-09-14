package web3jv.jsonrpc;

import java.util.List;

public class RawBody implements RequestBody {

    private String jsonrpc;
    private String method;
    private List<String> params;
    private String id;

    public RawBody() {
    }

    public RawBody(String jsonrpc, String method, List<String> params, String id) {
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
    public void setParams(List<String> params) {
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
    public List<String> getParams() {
        return params;
    }

    @Override
    public String getId() {
        return id;
    }
}
