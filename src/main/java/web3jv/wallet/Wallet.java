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

    public static void main(String[] args) {
        String priKey = "fdd8b595a0ba6ba01c04ab62bd1ab0fb6464fe44a3f32ac07ef236298e97e1aa";
        System.out.println(checkAddressEIP55("0x9fab8c7a16b7cbaa1cf2b8568e8d1b3a59aeb827"));

    }

    public static String generatePrivateKey() {
        Random random = new Random();
        StringBuilder privateKey = new StringBuilder();
        for (int i = 0; i < 64; i++) {
            privateKey.append(Integer.toHexString(random.nextInt(16)));
        }

        return privateKey.toString();
    }

    public static String getPublicKey(String priKey) {
        byte[] priByte = new BigInteger(priKey, 16).toByteArray(); // it adds 00 padding at the beginning
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECPoint pointQ = params.getG().multiply(new BigInteger(priByte));

        return Hex.toHexString(pointQ.getEncoded(false)).substring(2);
    }

    public static String getKeccack256HexString(String publicKey) {
        Keccak.DigestKeccak keccak = new Keccak.Digest256();
        byte[] bytes = ByteUtils.fromHexString(publicKey);
        String hexed = Hex.toHexString(keccak.digest(bytes));

        return hexed.substring(hexed.length() - 40);
    }

    public static String getAddress(String pubKey) {
        return "0x" + getKeccack256HexString(pubKey);
    }

    public static boolean checkAddressEIP55(String address) {
        String target = address.startsWith("0x") ? address.substring(2) : address;
        String lower = target.toLowerCase();
        char[] checksum = getKeccack256HexString(lower).toCharArray();
        System.out.println(getKeccack256HexString(lower));
        char[] subject = target.toCharArray();
        for (int i = 0; i < subject.length; i++) {
            if (Character.isUpperCase(subject[i])) {
                return checksum[i] >= 56;
            }
        }

        return false;
    }

}