package web3jv.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class Sign {

    public static String sign(byte[] transactionHash, String privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECDomainParameters domain = new ECDomainParameters(params.getCurve(), params.getG(), params.getN());
        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(new BigInteger((new BigInteger(privateKey, 16)).toByteArray()), domain);

        signer.init(true, priKey);

        BigInteger[] sigs = signer.generateSignature(new Keccak.Digest256().digest(transactionHash));
        BigInteger r = sigs[0], s = sigs[1];

        BigInteger otherS = params.getN().subtract(s);
        if (s.compareTo(otherS) == 0) {
            s = otherS;
        }

        return Hex.toHexString(r.toByteArray()) + Hex.toHexString(s.toByteArray());
    }

}

