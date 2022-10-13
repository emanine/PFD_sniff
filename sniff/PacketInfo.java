package sniff;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;

import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

public class PacketInfo {
	
	public String type;
	
	public String srcIp;
	public int srcPort;
	public String protoctype;

	
	
	public String destIp;
	public int destPort;
	String hardware;
	
	public byte[] data;
	public String strData = null;
	//arp
	public String gettarget,targetprotocol,getsender,sender;
	//tcp
	boolean psh;
	boolean ack;
	int wd;
	boolean fn,sy,rt,ug, rsv1, rsv2;
	Long acknum,seq;
	//http
	
	 
	//udp
	int lgt;
	//icmp
	int cd,idd,sequ;
	InetAddress redirect;
	String mask;
	Long time;
	//ip
	int version,prt,lg,idt,of,lt,prct;
	boolean tfl,rfl,df,mf;
	String srchost,dschost;
	
	public ArrayList<String> saveFormat = new ArrayList<String>();
	
	
	public PacketInfo(Packet packet) {
		
		if(packet instanceof TCPPacket) {
			TCPPacket tcp = (TCPPacket)packet;
			this.type = "TCP";
			saveFormat.add(this.type);

			this.srcIp = tcp.src_ip.toString().substring(1);
			saveFormat.add(this.srcIp);
			
			this.destIp = tcp.dst_ip.toString().substring(1);
			saveFormat.add(this.destIp);
			
			this.srcPort = tcp.src_port;
			saveFormat.add(this.srcPort + "");
			
			this.destPort = tcp.dst_port;
			saveFormat.add(this.destPort + "");
			
			this.seq=tcp.sequence;
			saveFormat.add(this.seq + "");
			
			this.acknum=tcp.ack_num;
			saveFormat.add(this.acknum + "");
			
			this.ug=tcp.urg;
			saveFormat.add(this.ug + "");
			
			this.ack =tcp.ack;
			saveFormat.add(this.ack + "");
			
			this.psh =tcp.psh;
			saveFormat.add(this.psh + "");
			
			this.rt=tcp.rst;
			saveFormat.add(this.rt + "");
			
			this.sy=tcp.syn;
			saveFormat.add(this.sy + "");
			
			this.fn=tcp.fin;
			saveFormat.add(this.fn + "");
			
			this.rsv1 = tcp.rsv1;
			saveFormat.add(this.rsv1 + "");
			
			this.rsv2 = tcp.rsv2;
			saveFormat.add(this.rsv2 + "");
			
			this.wd=tcp.window;
			saveFormat.add(this.wd + "");
			
			this.data = tcp.data;
			saveFormat.add(this.getData());
			
//			System.out.println(saveFormat.toString().replaceAll("[,][ ]"," / ").replaceAll("\\[|\\]", ""));
			/*TCPPacket tcpPacket = (TCPPacket) captor.getPacket();
System.out.println(new String(tcpPacket.header));*/
		}
		else if(packet instanceof UDPPacket) {
		
			UDPPacket udp = (UDPPacket)packet;
			
			this.type = "UDP";
			saveFormat.add(this.type);
			
			this.srcIp = udp.src_ip.toString().substring(1);
			saveFormat.add(this.srcIp);
			
			this.destIp = udp.dst_ip.toString().substring(1);
			saveFormat.add(this.destIp);
			
			this.srcPort = udp.src_port;
			saveFormat.add(this.srcPort + "");
			
			this.destPort = udp.dst_port;
			saveFormat.add(this.destPort + "");
			
			this.lgt=udp.length;
			saveFormat.add(this.lgt + "");
			
			this.data = udp.data;
			saveFormat.add(this.getData());
		}
		else if(packet instanceof ICMPPacket) {
			ICMPPacket icmp = (ICMPPacket)packet;
			
			this.type = "ICMP";
			saveFormat.add(this.type);
			
			this.srcIp = icmp.src_ip.toString().substring(1);
			saveFormat.add(this.srcIp);
			
			this.destIp = icmp.dst_ip.toString().substring(1);
			saveFormat.add(this.destIp);
			
			this.cd=icmp.code;
			saveFormat.add(this.cd + "");
			
			this.idd=icmp.id;
			saveFormat.add(this.idd + "");
			
			this.sequ=icmp.seq;
			saveFormat.add(this.sequ + "");
			
			this.redirect=icmp.redir_ip;
			saveFormat.add(this.redirect + "");
			this.data = icmp.data;
			saveFormat.add(this.getData());
			
			/*this.mask=(icmp.subnetmask>>12)+"."+
            ((icmp.subnetmask>>8)&0xff)+"."+
            ((icmp.subnetmask>>4)&0xff)+"."+
            (icmp.subnetmask&0xff)+".";
           this.time=(long) (icmp.orig_timestamp+icmp.recv_timestamp+icmp.trans_timestamp);*/
			
		}
		else if(packet instanceof IPPacket) {
			IPPacket ip = (IPPacket)packet;
			
			this.type = "IP";
			saveFormat.add(this.type);
			
			this.srcIp = ip.src_ip.toString().substring(1);
			saveFormat.add(this.srcIp);
			
			this.destIp = ip.dst_ip.toString().substring(1);
			saveFormat.add(this.destIp);
			
			this.version=4;
			saveFormat.add(this.version + "");
			
			this.prt=ip.priority;
			saveFormat.add(this.prt + "");
			
			this.tfl=ip.t_flag;
			saveFormat.add(this.tfl + "");
			
			this.rfl=ip.r_flag;
			saveFormat.add(this.rfl + "");
			
			this.lg=ip.length;
			saveFormat.add(this.lg + "");
			
			this.idt=ip.ident;
			saveFormat.add(this.idt + "");
			
			this.df=ip.dont_frag;
			saveFormat.add(this.df + "");
			
			this.mf=ip.more_frag;
			saveFormat.add(this.mf + "");
			
			this.of=ip.offset;
			saveFormat.add(this.of + "");
			
			this.lt=ip.hop_limit;
			saveFormat.add(this.lt + "");
			
			this.prct=ip.protocol;
			saveFormat.add(this.prct + "");
			
			this.srchost=ip.src_ip.getHostAddress();
			saveFormat.add(this.srchost);
			
			this.dschost=ip.dst_ip.getHostAddress();
			saveFormat.add(this.dschost);
			
			this.data = ip.data;
			saveFormat.add(this.getData());
		}
		else if(packet instanceof ARPPacket) {
			
		
			ARPPacket arp = (ARPPacket)packet;
			
			this.type = "ARP";
			saveFormat.add(this.type);
			
			this.hardware =(String) arp.getTargetHardwareAddress();
			saveFormat.add(this.hardware);
			
			this.data = arp.data;
			saveFormat.add(this.getData());
			//this.protoctype=(String) arp.getSenderProtocolAddress();
			try {
				this.targetprotocol =(String) arp.getTargetProtocolAddress();
			} catch(Exception e) {
				this.targetprotocol = "";
			}
			saveFormat.add(this.targetprotocol);
			
			try {
				this.gettarget=(String) arp.getTargetHardwareAddress();
			} catch(Exception e) {
				this.gettarget = "";
			}
			saveFormat.add(this.gettarget);
			
			try {
				this.getsender=(String) arp.getSenderProtocolAddress();
			} catch(Exception e) {
				this.getsender = "";
			}
			saveFormat.add(this.getsender);
			
			try {
				this.sender=(String) arp.getSenderHardwareAddress();
			} catch(Exception e) {
				this.sender = "";
			}
			saveFormat.add(this.sender);
			
		}
	}
	
	
	//ouvrir
	
	public PacketInfo(String line) {
		String[] info = line.split(" / ");
		if(info[0].equals("TCP")) {
			this.type = "TCP";
			saveFormat.add(this.type);

			this.srcIp = info[1];
			saveFormat.add(this.srcIp);
			
			this.destIp = info[2];
			saveFormat.add(this.destIp);
			
			this.srcPort = Integer.parseInt(info[3]);
			saveFormat.add(this.srcPort + "");
			
			this.destPort = Integer.parseInt(info[4]);
			saveFormat.add(this.destPort + "");
			
			this.seq= Long.parseLong(info[5]);
			saveFormat.add(this.seq + "");
			
			this.acknum= Long.parseLong(info[6]);
			saveFormat.add(this.acknum + "");
			
			this.ug=info[7].equals("true");
			saveFormat.add(this.ug + "");
			
			this.ack = info[8].equals("true");
			saveFormat.add(this.ack + "");
			
			this.psh = info[9].equals("true");
			saveFormat.add(this.psh + "");
			
			this.rt=info[10].equals("true");
			saveFormat.add(this.rt + "");
			
			this.sy=info[11].equals("true");
			saveFormat.add(this.sy + "");
			
			this.fn=info[12].equals("true");
			saveFormat.add(this.fn + "");
			
			this.rsv1 = info[13].equals("true");
			saveFormat.add(this.rsv1 + "");
			
			this.rsv2 = info[14].equals("true");
			saveFormat.add(this.rsv2 + "");
			
			this.wd = Integer.parseInt(info[15]);
			saveFormat.add(this.wd + "");
			
			//this.data = info[16];
			String data;
			if(info.length > 16) {
				data = info[16];
			} else {
				data = "";
			}
			this.strData = data;
			saveFormat.add(data);
		} else if(info[0].equals("UDP")) {
			
			
			this.type = "UDP";
			saveFormat.add(this.type);

			this.srcIp = info[1];
			saveFormat.add(this.srcIp);
			
			this.destIp = info[2];
			saveFormat.add(this.destIp);
			
			this.srcPort = Integer.parseInt(info[3]);
			saveFormat.add(this.srcPort + "");
			
			this.destPort = Integer.parseInt(info[4]);
			saveFormat.add(this.destPort + "");
			
			this.lgt= Integer.parseInt(info[5]);
			saveFormat.add(this.seq + "");
			
			//this.data = info[16];
			String data;
			if(info.length > 6) {
				data = info[6];
			} else {
				data = "";
			}
			this.strData = data;
			saveFormat.add(data);
		} else if(info[0].equals("ICMP")) {
			
			
			this.type = "ICMP";
			saveFormat.add(this.type);

			this.srcIp = info[1];
			saveFormat.add(this.srcIp);
			
			this.destIp = info[2];
			saveFormat.add(this.destIp);
			
			this.cd = Integer.parseInt(info[3]);
			saveFormat.add(this.cd + "");
			
			this.idd=Integer.parseInt(info[4]);
			saveFormat.add(this.idd + "");
			
			this.sequ=Integer.parseInt(info[5]);
			saveFormat.add(this.sequ + "");
			
			this.redirect=null; //info[6]
			saveFormat.add(this.redirect + "");
			
			String data;
			if(info.length > 7) {
				data = info[7];
			} else {
				data = "";
			}
			this.strData = data;
			saveFormat.add(data);			
		}  else if(info[0].equals("ICMP")) {
			
			
			this.type = "IP";
			saveFormat.add(this.type);
			
			
			this.srcIp = info[1];
			saveFormat.add(this.srcIp);
			
			this.destIp = info[2];
			saveFormat.add(this.destIp);
			
			this.version=Integer.parseInt(info[3]);
			saveFormat.add(this.version + "");
			
			this.prt=Integer.parseInt(info[4]);
			saveFormat.add(this.prt + "");
			
			this.tfl=info[5].equals("true");
			saveFormat.add(this.tfl + "");
			
			this.rfl=info[6].equals("true");
			saveFormat.add(this.rfl + "");
			
			this.lg=Integer.parseInt(info[7]);
			saveFormat.add(this.lg + "");
			
			this.idt=Integer.parseInt(info[8]);
			saveFormat.add(this.idt + "");
			
			this.df=info[9].equals("true");
			saveFormat.add(this.df + "");
			
			this.mf=info[10].equals("true");
			saveFormat.add(this.mf + "");
			
			this.of=Integer.parseInt(info[11]);
			saveFormat.add(this.of + "");
			
			this.lt=Integer.parseInt(info[12]);
			saveFormat.add(this.lt + "");
			
			this.prct=Integer.parseInt(info[13]);
			saveFormat.add(this.prct + "");
			
			this.srchost=info[14];
			saveFormat.add(this.srchost);
			
			this.dschost=info[15];
			saveFormat.add(this.dschost);
			
			
			String data;
			if(info.length > 16) {
				data = info[16];
			} else {
				data = "";
			}
			this.strData = data;
			saveFormat.add(data);		
		} else if(info[0].equals("ARP")) {

			this.type = "ARP";
			saveFormat.add(this.type);
			
			this.hardware =info[1];
			saveFormat.add(this.hardware);
			
			String data;
			if(info.length > 2) {
				data = info[2];
			} else {
				data = "";
			}
			this.strData = data;
			saveFormat.add(data);
			//this.protoctype=(String) arp.getSenderProtocolAddress();
			
			try {
				this.targetprotocol =info[3];
			} catch(Exception e) {
				this.targetprotocol = "";
			}
			saveFormat.add(this.targetprotocol);
			
			try {
				this.gettarget=info[4];
			} catch(Exception e) {
				this.gettarget = "";
			}
			saveFormat.add(this.gettarget);
			
			try {
				this.getsender=info[5];
			} catch(Exception e) {
				this.getsender = "";
			}
			saveFormat.add(this.getsender);
			
			try {
				this.sender=info[6];
			} catch(Exception e) {
				this.sender = "";
			}
			saveFormat.add(this.sender);
					
		}
	}
	
	public String getData() {
		if(this.strData != null) {
			return strData;
		}
		if(this.data == null) {
			return null;
		}
		StringBuffer sb = new StringBuffer();
		for(byte b: this.data) {
			sb.append(String.format("%02x ", b));
		}
		return (strData = sb.toString());
	}
	
	
	
	public String toString() {
		
		return "  "+this.type + "    :              " + this.srcIp + "                                " + this.destIp
				+this.wd;
	}
}
