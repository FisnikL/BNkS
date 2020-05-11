import java.math.BigInteger;

public class SecondMessage {
    private BigInteger DHPublic;
    private Certificate certificate;
    private byte[] encryptedBytes;

    public SecondMessage(BigInteger DHPublic, byte[] encryptedBytes) {
        this.DHPublic = DHPublic;
        this.encryptedBytes = encryptedBytes;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public BigInteger getDHPublic() {
        return DHPublic;
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }
}
