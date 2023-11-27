package senscript;

import java.util.Base64;

import ascon.Ascon;
import device.SensorNode;

public class Command_ASCONDECIPHER extends Command{
	
	protected String message;
	protected String from;
	
	public Command_ASCONDECIPHER(SensorNode sensor, String message, String from) {
		this.sensor = sensor;
		this.message = message;
		this.from = from;
	}

	@Override
	public double execute() {
		if (sensor.dataAvailable()) {
			String rep = sensor.readMessage(message);
			
			String[] array = rep.split("-");
		      
	        byte[] m_sub = Base64.getDecoder().decode(array[0]);
	        byte[] nsec_sub = Base64.getDecoder().decode(array[2]);
	        int clen_sub = Integer.valueOf(array[4]);
	        byte[] c_sub = Base64.getDecoder().decode(array[3]);
	        byte[] a_sub = Base64.getDecoder().decode(array[5]);
	        byte[] npub_sub = Base64.getDecoder().decode(array[7]);
	        byte[] k_sub = Base64.getDecoder().decode(array[8]);
	        
	        int mlen = Ascon.crypto_aead_decrypt(m_sub, 0, nsec_sub, c_sub, clen_sub, a_sub, 0, npub_sub, k_sub);
			
		    if (mlen == -1) {
		        System.out.printf("verification failed\n");
		        System.out.printf("\n");
		    }
		    else {
		    	System.out.printf("communication succeded\n");
		        System.out.printf("text: " + new String(m_sub));
		    }
	        return 0;
		}
		return 1;
	}

	
}
