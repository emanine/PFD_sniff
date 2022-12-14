package poison;
import java.net.InetAddress;
import java.util.ArrayList;


public class LANExplorer {
    public static ArrayList<String> getIPs(String cidrIp, String mask) {
        
    	int[] bounds = LANExplorer.rangeFromCidr(cidrIp, mask);
        
    	ArrayList<String> addresslist = new ArrayList<String>();
        for (int i = bounds[0]; i <= bounds[1]; i++) {
            String address = InetRange.intToIp(i);
            addresslist.add(address);
        }
        return addresslist;
    }

    public static int[] rangeFromCidr(String cidrIp, String mask) {   
        
        int[] result = new int[2];
        int network = InetRange.ipToInt(cidrIp) & InetRange.ipToInt(mask);
        int broadcast = InetRange.ipToInt(cidrIp) | ~InetRange.ipToInt(mask);
        
        result[0] = network + 1;
        result[1] = broadcast - 1; 
        return result;
    }

    static class InetRange {
        public static int ipToInt(String ipAddress) {
            try {
                byte[] bytes = InetAddress.getByName(ipAddress).getAddress();
                int octet1 = (bytes[0] & 0xFF) << 24;
                int octet2 = (bytes[1] & 0xFF) << 16;
                int octet3 = (bytes[2] & 0xFF) << 8;
                int octet4 = bytes[3] & 0xFF;
                int address = octet1 | octet2 | octet3 | octet4;

                return address;
            } catch (Exception e) {
                e.printStackTrace();

                return 0;
            }
        }

        public static String intToIp(int ipAddress) {
            int octet1 = (ipAddress & 0xFF000000) >>> 24;
            int octet2 = (ipAddress & 0xFF0000) >>> 16;
            int octet3 = (ipAddress & 0xFF00) >>> 8;
            int octet4 = ipAddress & 0xFF;

            return new StringBuffer().append(octet1).append('.').append(octet2)
                                     .append('.').append(octet3).append('.')
                                     .append(octet4).toString();
        }
    }
}