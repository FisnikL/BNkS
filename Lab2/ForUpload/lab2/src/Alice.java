import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Alice {
    private static SecretKey secretKey;
    private String ID;
    private static Cipher cipher;
    private byte[] nonce; // 16 bytes

    // FromKDC
    private SecretKey sessionKeyFromKDC;
    private byte[] yB;

    public Alice() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.secretKey = CustomKeyGenerator.getKey();
        this.ID = "IDA";
        cipher = Cipher.getInstance("AES/ECB/NoPadding");
    }

    public void sendKeyToKDC(KDC kdc) {
        kdc.addKey(ID, secretKey);
        System.out.println("ALICE - KEY -> KDC");
    }

    public void sendRequestToKDC(KDC kdc, Bob bob) {
        this.nonce = generateNonce();
        byte[] idA = ID.getBytes();
        byte[] idB = bob.getID().getBytes();

        RequestToKDC requestToKDC = new RequestToKDC(idA, idB, this.nonce);
        System.out.println("ALICE - REQUEST -> KDC");
        kdc.acceptRequest(requestToKDC);
    }

    private byte[] generateNonce(){
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[128/8];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public void acceptResponse(ResponseFromKDC response) {
        try {
            decryptYA(response.yA);
            this.yB = response.yB;
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private void decryptYA(byte[] yA) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] yADecrypted = cipher.doFinal(yA);

        byte[] sessionKeyBytes = new byte[16];
        byte[] rABytes = new byte[16];
        byte[] TBytes = new byte[13];
        byte[] idBBytes = new byte[3];

        for(int i = 0; i < 16; ++i){
            sessionKeyBytes[i] = yADecrypted[i];
        }

        for(int i = 16; i < 16 + 16; ++i){
            rABytes[i - 16] = yADecrypted[i];
        }

        for(int i = 32; i < 32 + 13; ++i){
            TBytes[i-32] = yADecrypted[i];
        }

        for(int i = 48; i < 48 + 3; ++i){
            idBBytes[i - 48] = yADecrypted[i];
        }

        if(!verifyNonce(this.nonce, rABytes)){
            // THROW EXCEPTION
            System.out.println("NONCE VERIFICATION FAILED!");
        }

        if(!verifyIDB(idBBytes)){
            // THROW EXCEPTION
            System.out.println("IDB VERIFICATION FAILED!");
        }

        if(!verifyLifetime(TBytes)){
            // THROW EXCEPTION
            System.out.println("TIMELIFE VERIFICATION FAILED!");
        }

        this.sessionKeyFromKDC = new SecretKeySpec(sessionKeyBytes, "AES");
    }

    private boolean verifyLifetime(byte[] tBytes) {
        long T = Long.parseLong(new String(tBytes));
        if(System.currentTimeMillis() < T){
            return true;
        }
        return false;
    }

    private boolean verifyIDB(byte[] IDB) {
        if(new String(IDB).equals("IDB")){
            return true;
        }
        return false;
    }

    private boolean verifyNonce(byte[] nonce, byte[] nonceFromKDC) {
        for(int i = 0; i < 16; ++i){
            if(nonce[i] != nonceFromKDC[i]){
                return false;
            }
        }
        return true;
    }

    public void sendKDCDataToBob(Bob bob) {
        byte[] yAB = new byte[16 * 2];

        byte[] IDBytes = ID.getBytes();
        for(int i = 0; i < IDBytes.length; ++i){
            yAB[i] = IDBytes[i];
        }

        long timestamp = System.currentTimeMillis();
        byte[] timestampBytes = Long.toString(timestamp).getBytes();
        for(int i = 16; i < 16 + timestampBytes.length; ++i){
            yAB[i] = timestampBytes[i - 16];
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, sessionKeyFromKDC);
            byte[] yABEncrypted = cipher.doFinal(yAB);

            DataToBob dataToBob = new DataToBob(yABEncrypted, this.yB);
            System.out.println("ALICE - KDC DATA -> BOB");
            bob.acceptDataFromAlice(dataToBob);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    public void sendMessageToBob(Bob bob, String message){
        try {
            cipher.init(Cipher.ENCRYPT_MODE, sessionKeyFromKDC);
            String messageEncrypted = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
            System.out.println("ALICE - MESSAGE -> BOB\n\tMessage: " + message + "\n\tEncrypted: " + messageEncrypted);
            bob.acceptMessageFromAlice(messageEncrypted);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }
}
