public class FrameHeader {
    private byte[] sourceMAC;
    private byte[] destinationMAC;

    public FrameHeader(byte[] sourceMAC, byte[] destinationMAC){
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
    }

    public byte[] getSourceMAC() {
        return sourceMAC;
    }

    public byte[] getDestinationMAC() {
        return destinationMAC;
    }
}


