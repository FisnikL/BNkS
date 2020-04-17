public class RequestToKDC {
    public byte[] IDA;
    public byte[] IDB;
    public byte[] rA;

    public RequestToKDC(byte[] IDA, byte[] IDB, byte[] rA) {
        this.IDA = IDA;
        this.IDB = IDB;
        this.rA = rA;
    }
}
