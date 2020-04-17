import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class KDC {
    private static Map<String, SecretKey> keys = new HashMap<>();;
    private Cipher cipher;
    private ResponseFromKDC response;

    public KDC() throws NoSuchPaddingException, NoSuchAlgorithmException {
        cipher = Cipher.getInstance("AES/ECB/NoPadding");
    }

    public void addKey(String id, SecretKey key){
        keys.put(id, key);
    }

    public void acceptRequest(RequestToKDC request) {
        try {
            SecretKey sessionKey = CustomKeyGenerator.getKey();
            long lifetimeT = System.currentTimeMillis() + 10 * 60 * 1000;
            byte[] yA = encryptWithAlicesKey(sessionKey, request.rA, lifetimeT, request.IDB, request.IDA);
            byte[] yB = encryptWithBobsKey(sessionKey, request.IDA, lifetimeT, request.IDB);

            response = new ResponseFromKDC(yA, yB);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
    }

    private byte[] encryptWithAlicesKey(SecretKey sessionKey, byte[] rA, long T, byte[] idB, byte[] IDA) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey alicesKey = keys.get(new String(IDA));

        byte[] sessionKeyBytes = sessionKey.getEncoded();
        byte[] rABytes = rA;
        byte[] TBytes = Long.toString(T).getBytes();
        byte[] idBBytes = idB;

        byte[] yA = new byte[16 * 4];

//        System.out.println(sessionKeyBytes.length);
        for(int i = 0; i < sessionKeyBytes.length; ++i){
            yA[i] = sessionKeyBytes[i];
        }

//        System.out.println(rABytes.length);
        for(int i = 16; i < 16 + rABytes.length; ++i){
            yA[i] = rABytes[i - 16];
        }

//        System.out.println(TBytes.length);
        for(int i = 32; i < 32 + TBytes.length; ++i){
            yA[i] = TBytes[i-32];
        }

//        System.out.println(idBBytes.length);
        for(int i = 48; i < 48 + idBBytes.length; ++i){
            yA[i] = idBBytes[i - 48];
        }

        cipher.init(Cipher.ENCRYPT_MODE, alicesKey);
        byte[] yAEncrypted = cipher.doFinal(yA);

        return yAEncrypted;
    }

    private byte[] encryptWithBobsKey(SecretKey sessionKey, byte[] idA, long T, byte[] IDB) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKey bobsKey = keys.get(new String(IDB));

        byte[] sessionKeyBytes = sessionKey.getEncoded();
        byte[] idABytes = idA;
        byte[] TBytes = Long.toString(T).getBytes();

        byte[] yB = new byte[16 * 3];

        for(int i = 0; i < sessionKeyBytes.length; ++i){
            yB[i] = sessionKeyBytes[i];
        }

        for(int i = 16; i < 16 + idABytes.length; ++i){
            yB[i] = idABytes[i - 16];
        }

        for(int i = 32; i < 32 + TBytes.length; ++i){
            yB[i] = TBytes[i-32];
        }

        cipher.init(Cipher.ENCRYPT_MODE, bobsKey);
        byte[] yBEncrypted = cipher.doFinal(yB);

        return yBEncrypted;
    }

    public void respondToAlice(Alice alice){
        alice.acceptResponse(response);
    }
}
