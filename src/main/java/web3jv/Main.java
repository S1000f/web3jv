package web3jv;

import com.fasterxml.jackson.databind.ObjectMapper;
import web3jv.jsonrpc.Web3jv;
import web3jv.jsonrpc.transaction.Transaction;
import web3jv.utils.EtherUnit;
import web3jv.utils.Utils;

import java.io.IOException;
import java.math.BigInteger;

public class Main {

    private static ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) throws IOException {
        Web3jv web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        String address = "0xa11CB28A6066684DB968075101031d3151dC40ED";

        System.out.println(1 << 18);


    }
}
