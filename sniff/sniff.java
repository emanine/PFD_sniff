package sniff;

import jpcap.NetworkInterface;

import java.net.Inet4Address;

import jpcap.JpcapCaptor;
import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

public class sniff {
	private JpcapCaptor m_jpcaptor = null;
	private int MAX_PACKET_COUNT = 1000;
	private int PACKET_COUNT = 0;
	private Vue vue;
	public sniff(Vue vue) {
		this.vue = vue;
	}
	
	public void start() {
		// TODO Auto-generated method stub
		NetworkInterface networkInterface = Global.getDevice();
		if(networkInterface!=null) {
			try {
				
				this.m_jpcaptor=JpcapCaptor.openDevice(networkInterface, 65536, true, 10);
				
				PacketReceiver packetRecv= new PacketReceiver() {
                    	@Override
					public void receivePacket(Packet packet) {
                    		
                    	//LIMIT
                    	if(PACKET_COUNT == MAX_PACKET_COUNT) {
                    		vue.model.remove(0);
                    	} else {
                    		PACKET_COUNT++;
                    	}
                    	
                    	PacketInfo info = new PacketInfo(packet);
                    	
                    	//Add info
                    	try {
                    		vue.model.add(info);
                    	}catch(Exception e) {
                    		
                    	}
                    	
                    	//Scroll to Bottom
                    	vue.verticalbar.setValue( vue.verticalbar.getMaximum() );
					}
						
					};
				
				this.m_jpcaptor.loopPacket(-1,packetRecv);
			}
			catch(Exception exp) {
				exp.printStackTrace();
			}
		}}
		
	public void stop() {
		this.m_jpcaptor.breakLoop();
		System.out.println("stopped");
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
			

	}


