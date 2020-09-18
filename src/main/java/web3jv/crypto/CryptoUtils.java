package web3jv.crypto;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

public class CryptoUtils {

    public static String getKeccack256HexString(String publicKey) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        byte[] bytes = ByteUtils.fromHexString(publicKey); // keccak = 제로패딩 없어야 함

        return Hex.toHexString(keccak.digest(bytes));
    }

    public static String getKeccack256HexString(byte[] input) {
        return Hex.toHexString(getKeccack256Bytes(input));
    }

    public static byte[] getKeccack256Bytes(byte[] input) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        return keccak.digest(input);
    }

}

