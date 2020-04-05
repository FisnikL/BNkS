import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;

public class EncryptedFrame {
    private byte[] sourceMAC;
    private byte[] destinationMAC;
    private byte[] mic;
    private byte[] encryptedData;

    public EncryptedFrame(byte[] sourceMAC, byte[] destinationMAC, byte[] encryptedData, byte[] mic) {
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.mic = mic;
        this.encryptedData = encryptedData;
    }

    @Override
    public String toString(){
        StringBuilder sb = new StringBuilder();

        sb.append("Source MAC: ");
        sb.append(new String(sourceMAC) + "\n");
        sb.append("Destination MAC: ");
        sb.append(new String(destinationMAC) + "\n");
        sb.append("Payload: ");
        sb.append(Base64.getEncoder().encodeToString(encryptedData) + "\n");
        sb.append("MIC: ");
        sb.append(Base64.getEncoder().encodeToString(mic));

        return sb.toString();
    }

    public byte[] getSourceMAC() {
        return sourceMAC;
    }

    public byte[] getDestinationMAC() {
        return destinationMAC;
    }

    public byte[] getMic() {
        return mic;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }

    // ...


    public ClearTextFrame decryptFrame(Cipher micCipher, Cipher decryptionCipher) throws BadPaddingException, IllegalBlockSizeException {
        byte[] decryptedBytes = decryptBytes(decryptionCipher);

        byte[] mic = Arrays.copyOfRange(decryptedBytes, 0, 8);
        byte[] data = Arrays.copyOfRange(decryptedBytes, 16, decryptedBytes.length);

        if(verifyMIC(data, mic, micCipher)){
            ClearTextFrame clearTextFrame = new ClearTextFrame(new FrameHeader(sourceMAC, destinationMAC), data);
            return clearTextFrame;
        }else{
            throw new IllegalStateException();
        }
    }

    private byte[] decryptBytes(Cipher decryptionCipher) throws BadPaddingException, IllegalBlockSizeException {
        byte[] cipherText = new byte[16 + encryptedData.length];
        for(int i = 0; i < mic.length; ++i){
            cipherText[i] = mic[i];
        }
        for(int i = 0; i < encryptedData.length; ++i){
            cipherText[16 + i] = encryptedData[i];
        }
        byte[] decryptedBytes = decryptionCipher.doFinal(cipherText);
        return decryptedBytes;
    }

    private boolean verifyMIC(byte[] data, byte[] mic, Cipher cipher) throws BadPaddingException, IllegalBlockSizeException {
        byte[] decryptedFrame = new byte[sourceMAC.length + destinationMAC.length + data.length];
        int i = 0;
        for(int j = 0; j < sourceMAC.length; ++j){
            decryptedFrame[i] = sourceMAC[j];
            i++;
        }
        for(int j = 0; j < destinationMAC.length; ++j){
            decryptedFrame[i] = destinationMAC[j];
            i++;
        }
        for(int j = 0; j < data.length; ++j){
            decryptedFrame[i] = data[j];
            i++;
        }
        byte[] cbc_encrypted = cipher.doFinal(decryptedFrame);
        byte[] micVerify = new byte[8];
        for(int j = 0; j < 8; ++j){
            micVerify[j] = cbc_encrypted[cbc_encrypted.length - 16 + j];
        }
        for(int j = 0; j < micVerify.length; ++j){
            if(mic[j] != micVerify[j]){
                return false;
            }
        }
        return true;
    }
}
