import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CertificateAuthority {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private MessageDigest digest;
    private Map<String, PublicKey> saved;

    public CertificateAuthority() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyPairGenerator.generateKeyPair();

        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();

        this.digest = MessageDigest.getInstance("SHA-256");
        saved = new HashMap<>();

        System.out.println("A CertificateAuthority has been created with private key: ");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("and public key: ");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
    }

    public void addUser(User u){
        saved.put(u.getName(), u.getPublicKey());
        System.out.println("User " + u.getName() + " with public key: ");
        System.out.println(Base64.getEncoder().encodeToString(u.getPublicKey().getEncoded()));
        System.out.println("has been registered into the CA");
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Certificate sign(CertificateRequest cr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if(!saved.containsKey(cr.getName()) ||
                !Arrays.equals(saved.get(cr.getName()).getEncoded(), cr.getPublicKey())
        ){
            return null;
        }

        byte[] nameBytes = cr.getName().getBytes();
        byte[] publicKeyBytes = cr.getPublicKey();
        byte[] alphaBytes = cr.getAlpha().toByteArray();
        byte[] pBytes = cr.getP().toByteArray();

        byte[] bytesForSignature = new byte[nameBytes.length + cr.getPublicKey().length + alphaBytes.length + pBytes.length];

        int counter = 0;
        for(int i = 0; i < nameBytes.length; ++i){
            bytesForSignature[counter] = nameBytes[i];
            counter++;
        }

        for(int i = 0; i < publicKeyBytes.length; ++i){
            bytesForSignature[counter] = publicKeyBytes[i];
            counter++;
        }

        for(int i = 0; i < alphaBytes.length; ++i){
            bytesForSignature[counter] = alphaBytes[i];
            counter++;
        }

        for(int i = 0; i < pBytes.length; ++i){
            bytesForSignature[counter] = pBytes[i];
            counter++;
        }

        byte[] hashed = this.digest.digest(bytesForSignature);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
        byte[] signedHashedBytes = cipher.doFinal(hashed);

        System.out.println("\n The CA signs " + cr.getName() + " certificate\n");

        return new Certificate(cr.getName(), cr.getPublicKey(), cr.getAlpha(), cr.getP(), signedHashedBytes);
    }
}
