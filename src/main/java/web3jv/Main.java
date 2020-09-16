package web3jv;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.consensys.cava.bytes.Bytes;
import net.consensys.cava.rlp.RLP;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import web3jv.crypto.Sign;
import web3jv.jsonrpc.Web3jv;
import web3jv.jsonrpc.transaction.Transaction;

import java.math.BigInteger;

public class Main {

    private static ObjectMapper mapper = new ObjectMapper();

    public static void main(String[] args) {
        Web3jv web3jv = new Web3jv("https://ropsten.infura.io/v3/ff7a2a6b2e054541a1b4bffe4c58bd11");
        String address = "0xa11CB28A6066684DB968075101031d3151dC40ED";

//        System.out.println(web3jv.ethGasPrice());
//        System.out.println(web3jv.ethGetBalance(address));
//        System.out.println(web3jv.ethGetTransactionCount(address));
//        System.out.println(web3jv.ethEstimateGas(address));
//        System.out.println(web3jv.ethBlockNumber());

        Bytes result = RLP.encodeByteArray(ByteUtils.fromHexString("0x3d"));
        System.out.println(Hex.toHexString(result.toArray()));

    }
}
