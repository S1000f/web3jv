package web3jv.crypto;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import web3jv.jsonrpc.transaction.EncoderProvider;
import web3jv.jsonrpc.transaction.Transaction;
import web3jv.utils.Utils;
import web3jv.wallet.Wallet;

import java.math.BigInteger;
import java.util.Arrays;

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

    public static <T extends Transaction> boolean validateSignedTx(
            T receivedTx,
            EncoderProvider encoder,
            String address,
            String chainId
    ) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");

        encoder.setNonce(receivedTx.getNonce());
        encoder.setGasPrice(receivedTx.getGasPrice());
        encoder.setGasLimit(receivedTx.getGasLimit());
        encoder.setTo(receivedTx.getTo());
        encoder.setValue(receivedTx.getValue());
        encoder.setData(receivedTx.getData());
        encoder.setV(chainId);
        encoder.setR("");
        encoder.setS("");
        byte[] messageHash = getKeccack256Bytes(encoder.encode());

        BigInteger r = new BigInteger(receivedTx.getR(), 16);
        BigInteger s = new BigInteger(receivedTx.getS(), 16);

        String cutAddress = address.startsWith("0x") ? address.substring(2).toLowerCase() : address.toLowerCase();
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignedMessage(params, messageHash, r, s, i);
            if (k != null &&
                    Wallet.getAddressNo0x(Utils.toHexStringNo0x(k.toByteArray())).equals(cutAddress)) {
                return true;
            }
        }

        return false;
    }

    public static BigInteger[] signMessageByECDSA(byte[] targetMessage, String HexPassword) {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        ECPrivateKeyParameters priKey =
                new ECPrivateKeyParameters(new BigInteger(HexPassword, 16), domain);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, priKey);

        byte[] messageHash = getKeccack256Bytes(targetMessage);

        BigInteger[] sigs = signer.generateSignature(messageHash);
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) > 0) {
            s = otherS;
        }

        return new BigInteger[] {r, s};
    }

    public static BigInteger recoverFromSignedMessage(
            ECNamedCurveParameterSpec params,
            byte[] messageHash,
            BigInteger r,
            BigInteger s,
            int recId
    ) {
        BigInteger n = params.getN();
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        BigInteger prime = SecP256K1Curve.q;
        if (x.compareTo(prime) >= 0) {
            return null;
        }

        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(x, 1 + x9.getByteLength(params.getCurve()));
        compEnc[0] = (byte) (((recId & 1) == 1) ? 0x03 : 0x02);
        ECPoint R = params.getCurve().decodePoint(compEnc);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash);
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(params.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);

        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

}

