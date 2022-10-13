package sniff;

import java.net.Inet4Address;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;

public class Global {
	public static String myHostIp = "192.168.1.103";
	
	public static String getHost() {
		return myHostIp;
	}
	
	public static NetworkInterfaceAddress get_inet4(NetworkInterface device) throws NullPointerException {
		if (device == null) throw new NullPointerException("No device has been given!");

		for(NetworkInterfaceAddress addr : device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;

		return null;
	}
	
	public static NetworkInterface getNetworkIDbyHostAddress(String strHostAddress){
		NetworkInterface net=null;
		NetworkInterface[] arrayNetwordInterface = JpcapCaptor.getDeviceList();
		for(NetworkInterface networkInterface : arrayNetwordInterface) {
			for(NetworkInterfaceAddress networkInterfaceAddress : networkInterface.addresses) {
				if(networkInterfaceAddress.address.getHostAddress().equals(strHostAddress)) {
					net=networkInterface;
					return net;
				}
			}
			
		}
		return net;
	}
	
	public static NetworkInterface myDevice = getNetworkIDbyHostAddress(getHost());
	
	public static NetworkInterface getDevice() {
		return myDevice;
	}
}
