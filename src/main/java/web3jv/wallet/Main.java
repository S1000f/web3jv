package web3jv.wallet;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        Web3jv web3jv = new Web3jv();
        web3jv.setEndpoint("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        web3jv.getClientVersion();


    }
}
