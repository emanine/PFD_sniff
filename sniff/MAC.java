package sniff;

public class MAC {
	public static byte[] StringToBytes(String macStr) {
		String[] parts = macStr.split(":");
		if(parts.length != 6) {
			parts = macStr.split("-");
		}
		if(parts.length != 6) {
			return null;
		}
		
		try {
			byte[] macBytes = new byte[] {
					(byte)Integer.parseInt(parts[0],16),
					(byte)Integer.parseInt(parts[1],16),
	                (byte)Integer.parseInt(parts[2],16),
	                (byte)Integer.parseInt(parts[3],16),
	                (byte)Integer.parseInt(parts[4],16),
	                (byte)Integer.parseInt(parts[5],16)
	                };
			
			return macBytes;
		} catch (Exception e) {
			// TODO: handle exception
			return null;
		}
	}
	
}
