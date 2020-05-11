import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {

        CertificateAuthority certificateAuthority = new CertificateAuthority();

        User Alice = new User("Alice");
        User Bob = new User("Bob");

        certificateAuthority.addUser(Alice);
        certificateAuthority.addUser(Bob);

        SecondMessage sm = Bob.receiveFirstMessage(Alice.generateFirstMessage(BigInteger.valueOf(5), BigInteger.valueOf(23)));
        sm.setCertificate(certificateAuthority.sign(Bob.sendCertificateRequest()));

        if(sm.getCertificate() != null){
            if(Alice.validateCertificate(sm.getCertificate(), certificateAuthority.getPublicKey())){
                ThirdMessage tm = Alice.validateSecondMessage(sm, Bob.getPublicKey());
                tm.setCertificate(certificateAuthority.sign(Alice.sendCertificateRequest()));
                if(tm.getCertificate() != null){
                    if(Bob.validateCertificate(tm.getCertificate(), certificateAuthority.getPublicKey())){
                        Bob.validateThirdMessage(tm, Alice.getPublicKey());
                    }
                }
            }
            else {
                System.out.println("FAILED");
            }
        }
    }
}
