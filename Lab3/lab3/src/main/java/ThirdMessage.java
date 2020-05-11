public class ThirdMessage {
    private Certificate certificate;
    private byte[] encryptedBytes;

    public ThirdMessage(byte[] encryptedBytes) {
        this.encryptedBytes = encryptedBytes;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }
}
