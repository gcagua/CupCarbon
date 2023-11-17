package senscript;

import ascon.Ascon;
import device.SensorNode;

public class Command_COMMUNICATE extends Command{
	
	public final static int MAXLEN = 65536;
	protected String plainText;
	protected String associatedData;
	protected String to;

	public Command_COMMUNICATE(SensorNode from, String plainText, String associatedData, String to){
		// Revisar la estructura del send
		this.sensor = from;
		this.plainText = plainText;
		this.associatedData = associatedData;
		this.to = to;
	}
	
	@Override
	public double execute() {
		// from.getScript().getVariableValue(arg[i]); para obtener los parámetros
		int i;
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

	    //for (i = 0; i < MLEN; ++i)
	      //a[i] = (byte) ('A' + i % 26);
	    //for (i = 0; i < MLEN; ++i)
	      //m[i] = (byte) ('a' + i % 26);
	    boolean failed = false;
	    for (alen = 0; alen <= MLEN; ++alen) {
	      for (mlen = 0; mlen <= MLEN; ++mlen) {
	    	  
	        clen = Ascon.crypto_aead_encrypt(c, clen, m, mlen, a, alen, nsec, npub, k);
	        mlen = Ascon.crypto_aead_decrypt(m, mlen, nsec, c, clen, a, alen, npub, k);
	        if (mlen != -1) {
	        	
	        } else
	          System.out.printf("verification failed\n");
	        System.out.printf("\n");
	        failed = true;
	      }
	    }
	    if (!failed) {
	    	System.out.printf("communication succeded\n");
	        System.out.printf("text: " + new String(m));
	    }
	    return 0;
	 }


}