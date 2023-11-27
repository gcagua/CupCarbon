package senscript;

import java.util.Base64;

import ascon.Ascon;
import device.DeviceList;
import device.MultiChannels;
import device.SensorNode;

public class Command_ASCONCIPHER extends Command{
	
	public final static int MAXLEN = 65536;
	protected String plainText;
	protected String associatedData;
	protected String to;

	public Command_ASCONCIPHER(SensorNode from, String plainText, String associatedData, String to){
		// Revisar la estructura del send
		this.sensor = from;
		this.plainText = plainText;
		this.associatedData = associatedData;
		this.to = to;
	}
	
	@Override
	public double execute() {
		// from.getScript().getVariableValue(arg[i]); para obtener los parámetros

	    int MLEN = 1;
	    
	    byte [] bytesPlainText = plainText.getBytes();
	    byte [] bytesAssociatedData = associatedData.getBytes();

	    int alen = bytesAssociatedData.length;
	    int mlen = bytesPlainText.length;
	    int clen = bytesPlainText.length + Ascon.CRYPTO_ABYTES;
	    byte a[] = bytesAssociatedData;
	    byte m[] = bytesPlainText;
	    byte c[] = new byte[m.length + Ascon.CRYPTO_ABYTES];
	    byte nsec[] = new byte[Ascon.CRYPTO_NSECBYTES];
	    byte npub[] =
	        {(byte) 0x7c, (byte) 0xc2, (byte) 0x54, (byte) 0xf8, (byte) 0x1b, (byte) 0xe8, (byte) 0xe7,
	            (byte) 0x8d, (byte) 0x76, (byte) 0x5a, (byte) 0x2e, (byte) 0x63, (byte) 0x33,
	            (byte) 0x9f, (byte) 0xc9, (byte) 0x9a};
	    byte k[] =
	        {0x67, (byte) 0xc6, 0x69, 0x73, 0x51, (byte) 0xff, 0x4a, (byte) 0xec, 0x29, (byte) 0xcd,
	            (byte) 0xba, (byte) 0xab, (byte) 0xf2, (byte) 0xfb, (byte) 0xe3, 0x46};

	    int destNodeId = Integer.valueOf(to);
	    SensorNode rnode = DeviceList.getSensorNodeById(destNodeId);
	    
	    //for (alen = 0; alen <= MLEN; ++alen) {
	    //  for (mlen = 0; mlen <= MLEN; ++mlen) {
	    mlen = 0;
	    alen = 0;
	    	  
	    //cosas que se transmiten y cambian: c, m, a, clen, nsec // npub y k no cambian
	    clen = Ascon.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
	    if (rnode != null) {
	    	if (sensor.canCommunicateWith(rnode)) {
	    		 String clen_text = Integer.toString(clen);
	    		 String c_text = Base64.getEncoder().encodeToString(c);
	    		 String m_text = Base64.getEncoder().encodeToString(m);
	    		 String a_text = Base64.getEncoder().encodeToString(a);
	    		 String nsec_text = Base64.getEncoder().encodeToString(nsec);
	    		 String npub_text = Base64.getEncoder().encodeToString(npub);
	    		 String k_text = Base64.getEncoder().encodeToString(k);
	    		 
	    		 String text2 = m_text + "-" + "0" + "-" + nsec_text + "-" + c_text + "-" + clen_text + "-" + a_text + "-" + "0" + "-" + npub_text + "-" + k_text;
	    	        
	    		MultiChannels.addPacketEvent(0, text2, sensor, rnode);
		    }
		}
	 
	    return 0;
	 }


}