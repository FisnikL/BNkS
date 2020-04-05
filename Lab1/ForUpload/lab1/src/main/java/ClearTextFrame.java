import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;

public class ClearTextFrame {
    private FrameHeader frameHeader;
    private byte[] data;

    public ClearTextFrame(FrameHeader frameHeader, byte[] data) {
        this.frameHeader = frameHeader;
        this.data = data;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("Source MAC: ");
        sb.append(new String(frameHeader.getSourceMAC()) + "\n");
        sb.append("Destination MAC: ");
        sb.append(new String(frameHeader.getDestinationMAC()) + "\n");
        sb.append("Payload: ");
        sb.append(new String(data) + "\n");

        return sb.toString();
    }
    // ...

    public EncryptedFrame encryptFrame(Cipher micCipher, Cipher encryptionCipher) throws BadPaddingException, IllegalBlockSizeException {
        byte[] mic = calculateMIC(micCipher);
        byte[] encryptedBytes = encryptData(encryptionCipher, mic);

        EncryptedFrame encryptedFrame = new EncryptedFrame(
                frameHeader.getSourceMAC(),
                frameHeader.getDestinationMAC(),
                Arrays.copyOfRange(encryptedBytes, 16, encryptedBytes.length),
                Arrays.copyOfRange(encryptedBytes, 0, 8)
        );
        return encryptedFrame;
    }


    private byte[] encryptData(Cipher cipher, byte[] mic) throws BadPaddingException, IllegalBlockSizeException {
        byte[] bytesToEncrypt = prepareDataToEncrypt(mic);
        byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);
        return encryptedBytes;
    }

    private byte[] prepareDataToEncrypt(byte[] mic){
        byte[] bytesToEncrypt = new byte[mic.length + 8 + data.length];
        for(int i = 0; i < mic.length; ++i){
            bytesToEncrypt[i] = mic[i];
        }
        for(int i = 0; i < data.length; ++i){
            bytesToEncrypt[i + mic.length + 8] = data[i];
        }
        return  bytesToEncrypt;
    }

    private byte[] calculateMIC(Cipher cipher) throws BadPaddingException, IllegalBlockSizeException {
        byte[] dataForCalculatingMIC = prepareDataForCalculatingMIC();
        byte[] cbc_encrypted = cipher.doFinal(dataForCalculatingMIC);
        // MIC is the first 8 bytes in the last 16 bytes
        byte[] mic = new byte[8];

        for(int i = 0; i < mic.length; ++i){
            mic[i] = cbc_encrypted[cbc_encrypted.length - 16 + i];
        }
        return mic;
    }

    private byte[] prepareDataForCalculatingMIC(){
        byte[] sourceMAC = frameHeader.getSourceMAC();
        byte[] destinationMAC = frameHeader.getDestinationMAC();
        byte[] bytes = new byte[sourceMAC.length + destinationMAC.length + this.data.length];
        int i = 0;
        for(int j = 0; j < sourceMAC.length; ++j){
            bytes[i] = sourceMAC[j];
            i++;
        }
        for(int j = 0; j < destinationMAC.length; ++j){
            bytes[i] = destinationMAC[j];
            i++;
        }
        for(int j = 0; j < data.length; ++j){
            bytes[i] = data[j];
            i++;
        }
        return bytes;
    }
}
