package web3jv.wallet;

import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Random;

public class Wallet {

    public String generatePrivateKey() {
        Random random = new Random();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            privateKey.append(Integer.toHexString(random.nextInt(16)));
        }

        return privateKey.toString();
    }

    public String getPublicKey(String priKey) {
        byte[] priByte = (new BigInteger(priKey, 16)).toByteArray(); // ec = 제로패딩 있어야 함
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = params.getG().multiply(new BigInteger(priByte));

        return Hex.toHexString(pointQ.getEncoded(false)).substring(2);
    }
    public String getAddress(String pubKey) {
        String uncut = getKeccack256HexString(pubKey);
        return "0x" + uncut.substring(uncut.length() - 40);
    }

    public static String getKeccack256HexString(String publicKey) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        byte[] bytes = ByteUtils.fromHexString(publicKey); // keccak = 제로패딩 없어야 함

        return Hex.toHexString(keccak.digest(bytes));
    }

    public static String getKeccack256HexString(byte[] input) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        return Hex.toHexString(keccak.digest(input));
    }

    public static boolean checkAddressEIP55(String address) {
        String target = address.startsWith("0x") ? address.substring(2) : address;
        String lower = target.toLowerCase();
        char[] checksum = getKeccack256HexString(lower.getBytes()).toCharArray();
        char[] subject = target.toCharArray();
        for (int i = 0; i < target.length(); i++) {
            if (Character.isUpperCase(subject[i]) && checksum[i] < 56) {
                return false;
            }
        }

        return true;
    }

    public static String encodeEIP55(String address) {
        String target = address.startsWith("0x") ? address.substring(2) : address;
        String lower = target.toLowerCase();
        String addressHash = getKeccack256HexString(lower.getBytes());
        char[] subject = target.toCharArray();
        char[] checksum = addressHash.toCharArray();
        for (int i = 0; i < subject.length; i++) {
            if (checksum[i] >= 56) {
                subject[i] = Character.toUpperCase(subject[i]);
            }
        }

        return "0x" + String.valueOf(subject);
    }


}