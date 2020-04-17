import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class Kerberos {
    private Alice alice;
    private Bob bob;
    private KDC kdc;

    public Kerberos() throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.alice = new Alice();
        this.bob = new Bob();
        this.kdc = new KDC();
    }

    public void startKerberosDemonstration(){
        sendKeysToKDC();
        sendRequestFromAliceToKDC();
        sendResponseFromKDCToAlice();
        sendKDCDataFromAliceToBob();
        sendMessageFromAliceToBob();
    }

    private void sendMessageFromAliceToBob() {
        String message = "Hello Bob ... This course is really interesting!";
        alice.sendMessageToBob(bob, message);
    }

    private void sendKDCDataFromAliceToBob() {
        alice.sendKDCDataToBob(bob);
    }

    private void sendResponseFromKDCToAlice() {
        System.out.println("KDC - RESPONSE -> ALICE");
        kdc.respondToAlice(alice);
    }

    private void sendKeysToKDC(){
        alice.sendKeyToKDC(kdc);
        bob.sendKeyToKDC(kdc);
    }

    private void sendRequestFromAliceToKDC(){
        alice.sendRequestToKDC(kdc, bob);
    }
}
