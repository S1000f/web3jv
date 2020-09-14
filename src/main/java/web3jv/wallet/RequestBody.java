package web3jv.wallet;

import java.util.List;

public interface RequestBody {
    void setMethod(String method);
    void setParams(List<String> list);
    void setId(String id);
}
