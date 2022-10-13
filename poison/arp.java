package poison;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;


public class arp {
	private NetworkInterface device;
	private ARPPacket packet;
	
	private Inet4Address dest_ip;
	private byte [] dest_mac;
	
	
	private EthernetPacket generate_ethernet_packet(byte[] dest_mac) throws NullPointerException {
		if (this.device == null) throw new NullPointerException("No device has been given!");
		
		
		EthernetPacket ether = new EthernetPacket();
		ether.frametype = EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac = this.device.mac_address;
		ether.dst_mac = dest_mac;
		
		
		this.packet.datalink = ether;
		
		return ether;
	}
	
	
	private EthernetPacket generate_ethernet_packet(byte[] official_mac,byte[] dest_mac) throws NullPointerException {
		if (this.device == null) throw new NullPointerException("No device has been given!");
		
		
		EthernetPacket ether = new EthernetPacket();
		ether.frametype = EthernetPacket.ETHERTYPE_ARP;
		ether.src_mac = official_mac;
		ether.dst_mac = dest_mac;
		
		
		this.packet.datalink = ether;
		
		return ether;
	}
	
	
	private NetworkInterfaceAddress get_inet4() throws NullPointerException {
		if (this.device == null) throw new NullPointerException("No device has been given! ");
		
		for(NetworkInterfaceAddress addr : this.device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;
				
		return null;
	}
	
	
	private byte[] calculate_mac(String mac) {
		String[] macAddressParts = mac.split(":");
		
		
		byte[] macAddressBytes = new byte[6];
		for(int i=0; i<6; i++){
		    Integer hex = Integer.parseInt(macAddressParts[i], 16);
		    macAddressBytes[i] = hex.byteValue();
		}
		
		return macAddressBytes;
	}
	
	
	public arp(NetworkInterface device){
		this.device = device;
		
		
		this.packet = new ARPPacket();
		
		this.packet.hardtype = ARPPacket.HARDTYPE_ETHER;
		this.packet.prototype = ARPPacket.PROTOTYPE_IP;
		this.packet.hlen = 6; 
		this.packet.plen = 4; 

	}
	
	public ARPPacket build_request_packet(String dest_ip) throws NullPointerException, UnknownHostException {
		if (this.device == null) throw new NullPointerException("No device has been given!");
		
		byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
		
		this.packet.operation = ARPPacket.ARP_REQUEST;
		
		
		this.packet.sender_hardaddr = this.device.mac_address;
		this.packet.sender_protoaddr = this.get_inet4().address.getAddress();
		this.packet.target_hardaddr = broadcast;
		this.packet.target_protoaddr = InetAddress.getByName(dest_ip).getAddress();
		
		this.generate_ethernet_packet(broadcast);

		return this.packet;
	}
	
	
	public ARPPacket build_reply_packet(String dest_ip, String dest_mac , byte[] official_mac) throws NullPointerException, UnknownHostException {
		if (this.device == null) throw new NullPointerException("No device has been given!");
				
		this.packet.operation = ARPPacket.ARP_REPLY;
		this.packet.sender_hardaddr = this.device.mac_address;
		this.packet.sender_protoaddr = this.get_inet4().address.getAddress();
		this.packet.target_hardaddr = this.calculate_mac(dest_mac);
		this.packet.target_protoaddr = InetAddress.getByName(dest_ip).getAddress();
		
		this.generate_ethernet_packet(official_mac, this.calculate_mac(dest_mac));

		return this.packet;
	}
	
	
	public void buildDevice(String name, 
			String description, String datalink_name, 
			String datalink_description, byte[] mac, 
			String address, String subnet) throws UnknownHostException, SocketException{
		InetAddress iaddr = InetAddress.getByName(address);
		InetAddress iaddr_subnet = InetAddress.getByName(subnet);
		
		NetworkInterfaceAddress addr = new NetworkInterfaceAddress(iaddr.getAddress(), 
				iaddr_subnet.getAddress(), null, null);
		
		NetworkInterfaceAddress[] arr = new NetworkInterfaceAddress[1];
		arr[0] = addr;
	
		this.device = new NetworkInterface(name, description, false, datalink_name,
				datalink_description, mac, arr);
	}
	
	
	
	public NetworkInterface getDevice() {
		return device;
	}

	public void setDevice(NetworkInterface device) {
		this.device = device;
	}

	public ARPPacket getPacket() {
		return packet;
	}

	public void setPacket(ARPPacket packet) {
		this.packet = packet;
	}

	public Inet4Address getDest_ip() {
		return dest_ip;
	}

	public void setDest_ip(Inet4Address dest_ip) {
		this.dest_ip = dest_ip;
	}

	public byte[] getDest_mac() {
		return dest_mac;
	}

	public void setDest_mac(byte[] dest_mac) {
		this.dest_mac = dest_mac;
	}
	
	public void print() {
	}

}
