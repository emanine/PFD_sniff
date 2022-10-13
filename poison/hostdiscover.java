package poison;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;

import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;
import jpcap.packet.ARPPacket;
import jpcap.packet.TCPPacket;
import jpcap.NetworkInterface;

public class hostdiscover 
{
	private static HashMap<String, String> ip_mac_list;
	private static NetworkInterface device;
	private static byte[] gatewaymac;
	private static String gatewayip;
	private listener ARPListener;
	private sender ARPSender;
	private ArrayList<String> iplist;
	private PacketReceiver handler;
	private int sleepy;
	
	public hostdiscover(NetworkInterface mydevice) {
		this.handler = new packet_handler();
		device = mydevice;
		ip_mac_list = new HashMap<String, String>();
		this.sleepy = 100;
		String a = null;
		gatewaymac = null;
		gatewayip = null;

		try {
			this.ARPListener = new listener(device, this.handler);
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			this.ARPSender = new sender(device);
		} catch (Exception e) {
			e.printStackTrace();
		}

		NetworkInterfaceAddress inet4 = this.get_inet4(device);
		this.iplist = LANExplorer.getIPs(inet4.address.toString().split("/")[1], inet4.subnet.toString().split("/")[1]);
	}
	
	public void discover() {
		InetAddress pingAddr;
		
		try {
			pingAddr = InetAddress.getByName("www.google.com");
			this.ARPListener.setFilter("tcp and dst host "+pingAddr.getHostAddress(),true);
			this.ARPListener.getListener().setPacketReadTimeout(5000);
			this.ARPListener.start();

			while(true){
				try {
					new URL("http://www.google.com").openStream().close();
				}catch (Exception e){
					e.printStackTrace();
				}

				if(gatewaymac != null)
					break;
			}

		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		}

		
		try {
			Thread.sleep(500);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		}

		this.ARPListener.setFilter("arp", true);
		for (String ipaddr : this.iplist) {
			arp packet = new arp(device);
			try {
				
				Thread.sleep(this.sleepy);

				ARPPacket pack = packet.build_request_packet(ipaddr);
				

				this.ARPSender.send(pack);
			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		try {
			Thread.sleep(3000);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		}
		
		System.out.println();
		
		System.out.println(ip_mac_list.keySet().toString()+"\n");

		if(gatewayip == null){
			System.out.println("ERROR: No gateway found, try again later..");
			System.exit(1);
		}
		
		this.ARPListener.finish();
	}

	private NetworkInterfaceAddress get_inet4(NetworkInterface device) throws NullPointerException {
		if (device == null) throw new NullPointerException("ERROR: No device has been given!");

		for(NetworkInterfaceAddress addr : device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;

		return null;
	}
	
	public HashMap<String, String> getHosts(){
		return ip_mac_list;
	}

	public String getGatewayIp(){
		return gatewayip;
	}
	
	class packet_handler implements PacketReceiver {
		@Override
		public void receivePacket(Packet p_temp){
			if(p_temp instanceof ARPPacket){
				
				ARPPacket p=(ARPPacket)p_temp;
				if (p.operation == ARPPacket.ARP_REPLY){

					String srcip = p.getSenderProtocolAddress().toString().split("/")[1];
					if (ip_mac_list.containsKey(srcip)) return;
						if(gatewayip == null){
							if(Arrays.equals(gatewaymac , p.sender_hardaddr)){
								gatewayip = srcip;
								
							}
						}
						ip_mac_list.put(srcip,
								p.getSenderHardwareAddress().toString());

						
				}
			}
			else if(p_temp instanceof TCPPacket){
				if(!Arrays.equals(((EthernetPacket)p_temp.datalink).dst_mac,device.mac_address))
					gatewaymac = ((EthernetPacket)p_temp.datalink).dst_mac;
			}
		}
	}
}