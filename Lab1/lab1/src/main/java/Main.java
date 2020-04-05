import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class Main {

    public static ClearTextFrame generateClearTextFrame() throws UnsupportedEncodingException {
        String sourceMAC = "E8:6A:23:A4:E8:51";
        String destinationMAC = "34:40:10:2A:15:2A";
        FrameHeader frameHeader = new FrameHeader(
                sourceMAC.getBytes("UTF-8"),
                destinationMAC.getBytes("UTF-8")
        );
        String data = "ahhh ... i'm tired of this lab :S:S:S";
        ClearTextFrame clearTextFrame = new ClearTextFrame(frameHeader, data.getBytes("UTF-8"));

        return clearTextFrame;
    }


    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        try{
            CCMProtocol CCMProtocol = new CCMProtocol();

            System.out.println("ENCRYPTION: ");
            EncryptedFrame encryptedFrame = CCMProtocol.encryptFrame(generateClearTextFrame());
            System.out.println(encryptedFrame);
            System.out.println();
            //        encryptedFrame.getSourceMAC()[3] = new Byte("0");
                    encryptedFrame.getDestinationMAC()[3] = new Byte("0");
            //        encryptedFrame.getMic()[2] = new Byte("0");
            //        encryptedFrame.getEncryptedData()[5] = new Byte("0");
            ClearTextFrame decryptedFrame = CCMProtocol.decryptFrame(encryptedFrame);
            System.out.println("DECRYPTION: ");
            System.out.println(decryptedFrame);
        }
        catch(IllegalStateException | NoSuchAlgorithmException | NoSuchPaddingException e){
            System.out.println("IllegalStateException");
        }
    }
}
