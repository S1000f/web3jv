package web3jv.wallet;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class Wallet {

    public static void main(String[] args) throws Exception {
        getAddress(generatePrivateKey());
    }

    public static String generatePrivateKey() {
        Random random = new Random();
        String privateKey = "";
        for (int i = 0; i < 64; i++) {
            privateKey += Integer.toHexString(random.nextInt(16));
        }

        return privateKey;
    }

    public static void getAddress(String priKey) throws Exception {

        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = params.getG().multiply(new BigInteger(1, new BigInteger(priKey, 16).toByteArray()));
        String publicKey = Hex.toHexString(pointQ.getEncoded(false));
        String key = publicKey.substring(2);

        System.out.println(publicKey);

        MessageDigest digest = MessageDigest.getInstance("SHA-256"); // Keccak
        byte[] hash = digest.digest(new BigInteger(key, 16).toByteArray());
        String keccacked = Hex.toHexString(hash);
        String address = keccacked.substring(24);

        System.out.println(address);

    }
}

