import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class User {
    private String name;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private MessageDigest digest;

    private BigInteger DHPrivate;
    private BigInteger DHPublic;

    private BigInteger alpha;
    private BigInteger p;

    private Key sharedKey;

    private BigInteger otherPersonDHValue;

    public User(String name) throws NoSuchAlgorithmException {
        this.name = name;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyPairGenerator.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
        this.digest = MessageDigest.getInstance("SHA-256");
    }

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setDHPrivate(BigInteger DHprivate) {
        this.DHPrivate = DHprivate;
    }

    public void setDHPublic(BigInteger alpha, BigInteger p) {
        this.DHPublic = alpha.modPow(DHPrivate, p);
    }

    public void setSharedKey(Key sharedKey) {
        this.sharedKey = sharedKey;
    }

    public FirstMessage generateFirstMessage(BigInteger alpha, BigInteger p){
        Random random = new Random();
        setDHPrivate(BigInteger.valueOf(random.nextLong()));
        setDHPublic(alpha, p);
        this.alpha = alpha;
        this.p = p;
        System.out.println(this.name + " sends the FIRST MESSAGE with the content: ");
        return new FirstMessage(this.alpha, this.p, this.DHPublic);
    }

    public SecondMessage receiveFirstMessage(FirstMessage fm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        this.alpha = fm.getAlpha();
        this.p = fm.getP();
        Random random = new Random();
        setDHPrivate(BigInteger.valueOf(random.nextLong()));
        setDHPublic(alpha, p);
        this.otherPersonDHValue = fm.getDHPublic();

        System.out.println(this.name + " receives the FIRST MESSAGE and generates his public DH parameter: " + this.DHPublic);

        // ayax = a^y, a^x
        byte[] ayax = new byte[16];

        byte[] thisDHPublicBytes = this.DHPublic.toByteArray();
        byte[] fmDHPublicBytes = fm.getDHPublic().toByteArray();

        int counter = 0;
        for(int i = 0; i < thisDHPublicBytes.length; ++i){
            ayax[counter++] = thisDHPublicBytes[i];
        }

        // fill with 0
        for(int i = thisDHPublicBytes.length; i < 8; ++i){
            ayax[counter++] = 0;
        }

        for(int i = 0; i < fmDHPublicBytes.length; ++i) {
            ayax[counter++] = fmDHPublicBytes[i];
        }

        // fill with 0
        for(int i = fmDHPublicBytes.length; i < 8; ++i){
            ayax[counter++] = 0;
        }

        byte[] hashed = digest.digest(ayax);

        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, this.privateKey);
        byte[] signedBytes = c.doFinal(hashed);

        BigInteger calculatedValue = fm.getDHPublic().modPow(this.DHPrivate, this.p);
        byte[] commonKeyBytes = calculatedValue.toByteArray();
        byte[] finalBytes = new byte[16];

        for(int i = 0; i < commonKeyBytes.length; ++i){
            finalBytes[i] = commonKeyBytes[i];
        }

        // fill with 0
        for(int i = commonKeyBytes.length; i < 8; ++i){
            finalBytes[i] = 0;
        }

        for(int i = commonKeyBytes.length; i < 16; ++i){
            finalBytes[i] = 0;
        }


        // Encryption with shared calculated key
        Cipher cipher = Cipher.getInstance("AES");
        Key key = new SecretKeySpec(finalBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] finalEncrypted = cipher.doFinal(signedBytes);

        setSharedKey(key);

        System.out.println(this.name + " generates the common key: " + Base64.getEncoder().encodeToString(this.sharedKey.getEncoded()));
        System.out.println(this.name + " sends his public DH parameter and the encrypted version of a^y and a^x");
        System.out.println("Public DH parameter: " + this.DHPublic);
        System.out.println("encrypted data:" + Base64.getEncoder().encodeToString(finalEncrypted));

        return new SecondMessage(this.DHPublic, finalEncrypted);
    }

    public CertificateRequest sendCertificateRequest()
    {
        return new CertificateRequest(this.name, this.getPublicKey().getEncoded(), this.alpha, this.p);
    }

    public boolean validateCertificate(Certificate certificate, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // decrypting with CA's public key
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decrypted = c.doFinal(certificate.getSignedBytes());

        // Testing
//        certificate.changeName("Oscar");

        byte[] nameBytes = certificate.getName().getBytes();
        byte[] publicKeyBytes = certificate.getPublicKey();
        byte[] alphaBytes = certificate.getAlpha().toByteArray();
        byte[] pBytes = certificate.getP().toByteArray();

        byte[] concatenated = new byte[nameBytes.length + publicKeyBytes.length + alphaBytes.length + pBytes.length];

        int counter = 0;
        for(int i = 0; i < nameBytes.length; ++i){
            concatenated[counter] = nameBytes[i];
            counter++;
        }

        for(int i = 0; i < publicKeyBytes.length; ++i){
            concatenated[counter] = publicKeyBytes[i];
            counter++;
        }

        for(int i = 0; i < alphaBytes.length; ++i){
            concatenated[counter] = alphaBytes[i];
            counter++;
        }

        for(int i = 0; i < pBytes.length; ++i){
            concatenated[counter] = pBytes[i];
            counter++;
        }

        byte[] hashed = this.digest.digest(concatenated);

        boolean result = Arrays.equals(hashed, decrypted);
        if(!result){
            System.out.println("\nCertificate not validated by " + this.getName() + "!\n");
            return false;
        }
        else{
            System.out.println("\nCertificate validated by " + this.getName() + "!\n");
            return true;
        }
    }

    public ThirdMessage validateSecondMessage(SecondMessage sm, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // decrypting using shared key
        BigInteger calculatedValue = sm.getDHPublic().modPow(this.DHPrivate, this.p);
        byte[] commonKeyBytes = calculatedValue.toByteArray();
        byte[] finalBytes = new byte[16];

        for(int i = 0; i < commonKeyBytes.length; ++i){
            finalBytes[i] = commonKeyBytes[i];
        }

        // fill with 0
        for(int i = commonKeyBytes.length; i < 16; ++i){
            finalBytes[i] = 0;
        }

        Cipher cipher = Cipher.getInstance("AES");
        Key sharedKey = new SecretKeySpec(finalBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, sharedKey);
        byte[] decrypted = cipher.doFinal(sm.getEncryptedBytes());

        // checking other's signature
        Cipher c1 = Cipher.getInstance("RSA");
        c1.init(Cipher.DECRYPT_MODE, key);
        byte[] finalDecrypted = c1.doFinal(decrypted);

        byte[] concatenated = new byte[16];

        byte[] smDHPublicBytes = sm.getDHPublic().toByteArray();
        byte[] thisDHPublicBytes = this.DHPublic.toByteArray();

        int counter = 0;
        for(int i = 0; i < smDHPublicBytes.length; ++i){
            concatenated[counter++] = smDHPublicBytes[i];
        }

        // fill with 0
        for(int i = smDHPublicBytes.length; i < 8; ++i){
            concatenated[counter++] = 0;
        }

        for(int i = 0; i < thisDHPublicBytes.length; ++i){
            concatenated[counter++] = thisDHPublicBytes[i];
        }

        // fill with 0
        for(int i = thisDHPublicBytes.length; i < 8; ++i){
            concatenated[counter++] = 0;
        }

        byte[] hashed = this.digest.digest(concatenated);

        boolean result = Arrays.equals(finalDecrypted, hashed);
        if(!result){
            System.out.println("\nSecond message not validated by " + this.getName() + "!\n");
            return null;
        }

        System.out.println("\nSecond message validated by " + this.getName() + "!\n");

        byte[] resultConcatenated = new byte[16];

        counter = 0;
        for(int i = 0; i < thisDHPublicBytes.length; ++i){
            resultConcatenated[counter++] = thisDHPublicBytes[i];
        }

        // fill with 0
        for(int i = thisDHPublicBytes.length; i < 8; ++i){
            resultConcatenated[counter++] = 0;
        }

        for(int i = 0; i < smDHPublicBytes.length; ++i){
            resultConcatenated[counter++] = smDHPublicBytes[i];
        }

        // fill with 0
        for(int i = smDHPublicBytes.length; i < 8; ++i){
            resultConcatenated[counter++] = 0;
        }

        byte[] resultHashed = this.digest.digest(resultConcatenated);

        // Signing
        Cipher c2 = Cipher.getInstance("RSA");
        c2.init(Cipher.ENCRYPT_MODE, this.privateKey);
        byte[] encryptedOnce = c2.doFinal(resultHashed);

        // Encrypting with shared key
        Cipher c3 = Cipher.getInstance("AES");
        c3.init(Cipher.ENCRYPT_MODE, sharedKey);
        byte[] finalEncrypted = c3.doFinal(encryptedOnce);

        setSharedKey(sharedKey);

        return new ThirdMessage(finalEncrypted);
    }

    public boolean validateThirdMessage(ThirdMessage tm, PublicKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Decrypting with shared key
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, this.sharedKey);
        byte[] decryptedOnce = c.doFinal(tm.getEncryptedBytes());

        // Checking other's signature
        Cipher c1 = Cipher.getInstance("RSA");
        c1.init(Cipher.DECRYPT_MODE, key);
        byte[] hashedDecrypted = c1.doFinal(decryptedOnce);

        byte[] resultConcatenated = new byte[16];

        byte[] otherPersonDHValueBytes = this.otherPersonDHValue.toByteArray();
        byte[] DHPublicBytes = this.DHPublic.toByteArray();

        int counter = 0;
        for(int i = 0; i < otherPersonDHValueBytes.length; ++i){
            resultConcatenated[counter++] = otherPersonDHValueBytes[i];
        }

        // fill with 0
        for(int i = otherPersonDHValueBytes.length; i < 8; ++i){
            resultConcatenated[counter++] = 0;
        }

        for(int i = 0; i < DHPublicBytes.length; ++i){
            resultConcatenated[counter++] = DHPublicBytes[i];
        }

        // fill with 0
        for(int i = DHPublicBytes.length; i < 8; ++i){
            resultConcatenated[counter++] = 0;
        }

        byte[] resultHashed = this.digest.digest(resultConcatenated);

        boolean result = Arrays.equals(hashedDecrypted, resultHashed);
        if(!result){
            System.out.println("Final step validation FAILED!\n");
            return false;
        }
        else{
            System.out.println("\nFinal step validation is SUCCESSFUL!\n");
            return true;
        }
    }
}
