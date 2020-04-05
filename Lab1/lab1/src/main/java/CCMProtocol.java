import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CCMProtocol {
    private SecretKey secretKey;
    private Cipher micCipher;
    private Cipher encryptionCipher;

    public CCMProtocol() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // GENERATE KEY
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 128;
        keyGenerator.init(keyBitSize, secureRandom);
        this.secretKey = keyGenerator.generateKey();
        // AES_CBC mode
        this.micCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // AES_CTR mode
        this.encryptionCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
    }
    // ...

    public EncryptedFrame encryptFrame(ClearTextFrame frame) throws IllegalStateException {
        try{
            micCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return frame.encryptFrame(micCipher, encryptionCipher);
        }catch(InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            throw new IllegalStateException();
        }
    }

    public ClearTextFrame decryptFrame(EncryptedFrame frame) throws IllegalStateException{
        try{
            encryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, encryptionCipher.getParameters());
            micCipher.init(Cipher.ENCRYPT_MODE, secretKey, micCipher.getParameters());
            return frame.decryptFrame(micCipher, encryptionCipher);
        }catch(InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e){
            throw new IllegalStateException();
        }
    }
}
