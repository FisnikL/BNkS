import java.math.BigInteger;

public class FirstMessage {
    private BigInteger alpha;
    private BigInteger p;
    private BigInteger DHPublic;

    public FirstMessage(BigInteger alpha, BigInteger p, BigInteger DHPublic){
        this.alpha = alpha;
        this.p = p;
        this.DHPublic = DHPublic;

        System.out.println("Alpha == " + this.alpha.longValue());
        System.out.println("P == " + this.p.longValue());
        System.out.println("DH Public for Alice == " + this.DHPublic.longValue());
    }

    public BigInteger getAlpha() {
        return alpha;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getDHPublic() {
        return DHPublic;
    }
}
