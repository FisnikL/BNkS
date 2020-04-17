import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Bob {
    private static SecretKey secretKey;
    private String ID;
    private Cipher cipher;

    // FromKDC
    private SecretKey sessionKeyFromKDC;

    // FROM yB
    private String IDA;

    public Bob() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.secretKey = CustomKeyGenerator.getKey();
        this.ID = "IDB";
        this.cipher = Cipher.getInstance("AES/ECB/NoPadding");
    }

    public String getID() {
        return ID;
    }

    public void sendKeyToKDC(KDC kdc) {
        kdc.addKey(ID, secretKey);
        System.out.println("BOB - KEY -> KDC");
    }

    public void acceptDataFromAlice(DataToBob dataToBob) {
        try {
            decryptYB(dataToBob.yB);
            decryptYAB(dataToBob.yAB);

            System.out.println("BOB ACCEPTED DATA SUCCESSFULLY!");
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }



    private void decryptYB(byte[] yB) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] yBDecrypted = cipher.doFinal(yB);

        byte[] sessionKeyBytes = new byte[16];
        for(int i = 0; i < 16; ++i){
            sessionKeyBytes[i] = yBDecrypted[i];
        }

        byte[] idABytes = new byte[3];
        for(int i = 16; i < 16 + 3; ++i){
            idABytes[i - 16] = yBDecrypted[i];
        }

        byte[] TBytes = new byte[13];
        for(int i = 32; i < 32 + 13; ++i){
            TBytes[i - 32] = yBDecrypted[i];
        }

        if(!verifyLifetime(TBytes)){
            // THROW EXCEPTION
            System.out.println("BOB: LIFETIME VERIFICATION FAILED!");
        }

        this.IDA = new String(idABytes);
        this.sessionKeyFromKDC = new SecretKeySpec(sessionKeyBytes, "AES");
    }

    private void decryptYAB(byte[] yAB) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, sessionKeyFromKDC);
        byte[] yABDecrypted = cipher.doFinal(yAB);

        byte[] IDABytes = new byte[3];
        for(int i = 0; i < 3; ++i){
            IDABytes[i] = yABDecrypted[i];
        }

        byte[] timestampBytes = new byte[13];
        for(int i = 16; i < 16 + 13; ++i){
            timestampBytes[i-16] = yABDecrypted[i];
        }

        if(!verifyIDA(IDABytes)){
            // THROW EXCEPTION
            System.out.println("BOB: IDA VERIFICATION FAILED!");
        }

        if(!verifyTimestamp(timestampBytes)){
            // THROW EXCEPTION
            System.out.println("BOB: TIMESTAMP VERIFICATION FAILED!");
        }
    }

    private boolean verifyTimestamp(byte[] timestampBytes) {
        long timestamp = Long.parseLong(new String(timestampBytes));
        if(System.currentTimeMillis() < timestamp + 30 * 1000){
            return true;
        }
        return false;
    }

    private boolean verifyLifetime(byte[] tBytes) {
        long lifetime = Long.parseLong(new String(tBytes));
        if(System.currentTimeMillis() < lifetime){
            return true;
        }
        return false;
    }

    private boolean verifyIDA(byte[] idABytes) {
        if(new String(idABytes).equals(this.IDA)){
            return true;
        }
        return false;
    }

    public void acceptMessageFromAlice(String message){
        byte[] messageEncrypted = Base64.getDecoder().decode(message);
        try {
            cipher.init(Cipher.DECRYPT_MODE, sessionKeyFromKDC);
            byte[] messageDecrypted = cipher.doFinal(messageEncrypted);
            System.out.println("BOB RECEIVED MESSAGE SUCCESSFULLY!\n\tEncrypted: " + message + "\n\tDecrypted: " + new String(messageDecrypted));
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
