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

        System.out.println(web3jv.ethGetTransactionCount("0xAAA4d18979F2d3A52c426574Ed5b444a8E496A5d"));
        System.out.println(web3jv.ethGasPrice());
        System.out.println(web3jv.ethEstimateGas("0xa11CB28A6066684DB968075101031d3151dC40ED"));
        System.out.println(Utils.toWeiBigDecimal("0.1", EtherUnit.ETHER).toBigInteger());


        Transaction transaction = Transaction.builder()
                .nonce(new BigInteger("0"))
                .gasPrice(new BigInteger("4000000000"))
                .gasLimit(web3jv.ethEstimateGas("0xa11CB28A6066684DB968075101031d3151dC40ED"))
                .to("a11CB28A6066684DB968075101031d3151dC40ED")
                .data("")
                .value(Utils.toWeiBigDecimal("0.01", EtherUnit.ETHER).toBigInteger())
                .v(Utils.toHexString(web3jv.netVersion()))
                .r("")
                .s("")
                .build();

        String rawTx = transaction.buildRawTransaction(
                web3jv,
                "28e0af3f15316ffb692fb4c73bf54d2d0eada493204b9a4cb7e2d10812e4a73e"
        );
        System.out.println(rawTx);

        String whatisit = web3jv.ethSendRawTransaction(rawTx);

    }
}
