package web3jv.jsonrpc.transaction;

import net.consensys.cava.bytes.Bytes;
import net.consensys.cava.rlp.RLP;
import web3jv.utils.Utils;

public class RlpDecoder {
    public static Transaction decoder(byte[] receivedTx) {
        Bytes wrapped = Bytes.wrap(receivedTx);
        Transaction transaction = new Transaction();

        return RLP.decodeList(wrapped, (reader) -> {
            transaction.setNonce(reader.readBigInteger());
            transaction.setGasPrice(reader.readBigInteger());
            transaction.setGasLimit(reader.readBigInteger());
            transaction.setTo(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setValue(reader.readBigInteger());
            transaction.setData(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setV(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setR(Utils.toHexStringNo0x(reader.readByteArray()));
            transaction.setS(Utils.toHexStringNo0x(reader.readByteArray()));
            return transaction;
        });
    }

    public static Transaction decoder(String receivedTx) {
        String cut = receivedTx.startsWith("0x") ? receivedTx.substring(2) : receivedTx;
        return decoder(Utils.toBytes(cut));
    }
}
