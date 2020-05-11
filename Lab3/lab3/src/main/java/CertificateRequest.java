import java.math.BigInteger;

public class CertificateRequest {
    private String name;
    private byte[] publicKey;
    private BigInteger alpha;
    private BigInteger p;

    public CertificateRequest(String name, byte[] publicKey, BigInteger alpha, BigInteger p) {
        this.name = name;
        this.publicKey = publicKey;
        this.alpha = alpha;
        this.p = p;
    }

    public String getName() {
        return name;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public BigInteger getAlpha() {
        return alpha;
    }

    public BigInteger getP() {
        return p;
    }
}
