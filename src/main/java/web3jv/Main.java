package web3jv;

import com.fasterxml.jackson.databind.ObjectMapper;
import web3jv.jsonrpc.ChainId;
import web3jv.jsonrpc.Web3jv;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.RlpEncoder;

import java.io.IOException;

public class Main {

    private static ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws IOException {
        Web3jv web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        String address = "0xa11CB28A6066684DB968075101031d3151dC40ED";

        EncoderProvider sd = new RlpEncoder();
        ChainId a = ChainId.ROPSTEN;
    }
}
