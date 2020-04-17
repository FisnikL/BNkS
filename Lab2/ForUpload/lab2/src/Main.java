import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        try {
            Kerberos kerberos = new Kerberos();
            kerberos.startKerberosDemonstration();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
