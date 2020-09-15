package web3jv;

import web3jv.jsonrpc.Web3jv;

import java.io.IOException;
import java.math.BigInteger;

public class Main {
    public static void main(String[] args) throws IOException {
        Web3jv web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        web3jv.setEndpoint("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");

        BigInteger balanceWei = web3jv.getBalance("0xa11CB28A6066684DB968075101031d3151dC40ED");

        System.out.println(balanceWei);

    }
}
