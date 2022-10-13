package sniff;

/*import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class Vue extends JFrame{
	sniff sniffer = new sniff(this);
	public PacketInfoModel model;
	public JButton startBtn = new JButton("Start");
	public JButton stopBtn = new JButton("Stop");
	public JScrollPane scrollPane;
	public JScrollBar verticalbar;
	
	public JTextArea txtArea = new JTextArea(40, 60);
	public JPanel txtAreaJp = new JPanel();
	
	public JPanel infoPanel = new JPanel(new GridLayout(1, 2));
	
	
	public JPanel buttons = new JPanel(new FlowLayout());
	
	
	//tree
	JTree tree;
	DefaultMutableTreeNode n1,n2,n3,n4,n5,n6;
	JScrollPane sc;
	JLabel jl=new JLabel("name");
	
	public Vue() {
		
		
		model = new PacketInfoModel();
		
		
		JList list = new JList();
		list.setModel(model);
		
		scrollPane = new JScrollPane();
		scrollPane.setViewportView(list);
		
		//ScrollBar
		verticalbar = scrollPane.getVerticalScrollBar();
		
		
		
		//make textarea break lines
		txtArea.setLineWrap(true);
		txtArea.setWrapStyleWord(true);
		txtAreaJp.add(txtArea);
		infoPanel.add(txtAreaJp);
		
		
		buttons.add(startBtn);
		buttons.add(stopBtn);
		//tree
		n1= new DefaultMutableTreeNode("game");
		n2= new DefaultMutableTreeNode("jeux");
		n3= new DefaultMutableTreeNode("loaba");
		n4= new DefaultMutableTreeNode("loaba");
		n5= new DefaultMutableTreeNode("loaba");
		n6= new DefaultMutableTreeNode("loaba");
		n1.add(n2);n1.add(n3);
		n4.add(n5);n4.add(n6);
		tree=new JTree(n1);//tree=new JTree(n4);
		sc=new JScrollPane(tree);
		infoPanel.add(sc);
		infoPanel.add(txtAreaJp);
		
		
		setLayout(new GridLayout(3, 1));
		add(buttons);
		add(scrollPane);
		add(infoPanel);
		//add(sc);
		
		setVisible(true);
		setSize(900, 600);
		
		startBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				CompletableFuture.runAsync(() -> {
					sniffer.start();
				});
			}
		});
		
		stopBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				sniffer.stop();
			}
		});
		
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				PacketInfo info = (PacketInfo)list.getSelectedValue();
				txtArea.setText(info.getData());
			}
		});
		
	}
}
*/


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import javax.swing.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;

//import javax.swing.JTree;
import javax.swing.tree.*;

public class Vue extends JFrame{
	
	protected static final String String = null;
	sniff sniffer = new sniff(this);
	public PacketInfoModel model;
	
	
	public JButton stopBtn = new JButton("Stop");
	public JScrollPane scrollPane;
	
	public JScrollBar verticalbar;
	public JTextArea txtArea = new JTextArea(10, 30);
	
	
	public JPanel txtAreaJp = new JPanel();
	public JPanel infoPanel = new JPanel(new GridLayout(1, 3));
	public JPanel buttons = new JPanel();
	public JPanel treeJp = new JPanel();

	public JMenu menufichier=new JMenu("fichier");
	public JMenuItem ouvrir = new JMenuItem("ouvrir");
	public JMenuItem save = new JMenuItem("save");
	public JMenuItem quitter = new JMenuItem("quitter");
	
	
	public JMenu menuNet=new JMenu("Network");
	public JMenuItem capture = new JMenuItem("Capture");
	public JMenuItem attack = new JMenuItem("Attack");
	
	
	public Vue() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		JMenuBar mymenubar=new JMenuBar();
		mymenubar.setBounds(0,20,900,50);
		
		
		mymenubar.add(menufichier);
		
		
		menuNet.add(capture);
		menuNet.add(attack);
		mymenubar.add(menuNet);
		
		
		quitter.setActionCommand("Quitter");
		
		
		menufichier.add(ouvrir);
		menufichier.add(save);
		menufichier.add(quitter);
		
		JLabel labelType=new JLabel("Type");
		JLabel labelName=new JLabel("adresse ip source");
		JLabel labeldestination=new JLabel("adresse ip destination ");
		
		
		buttons.setLayout(null);
		
		model = new PacketInfoModel();
		JList<PacketInfo> list = new JList<PacketInfo>();
		list.setModel(model);
		
		scrollPane = new JScrollPane();
		scrollPane.setViewportView(list);
		
		//ScrollBar
		verticalbar = scrollPane.getVerticalScrollBar();
		
		
		//make textarea break lines
		txtArea.setLineWrap(true);
		txtArea.setWrapStyleWord(true);
		JScrollPane txtScroll = new JScrollPane(txtArea);
		txtAreaJp.add(txtScroll);
		txtAreaJp.setVisible(false);
		
		infoPanel.add(txtAreaJp);
		
		
		
		JScrollPane scrollTree = new JScrollPane();
		scrollTree.setViewportView(treeJp);
		
		infoPanel.add(scrollTree);
		
		
		stopBtn.setBounds(750, 30, 100, 30);
		labelType.setBounds(20, 160, 150, 30);
		labelName.setBounds(100, 160, 150, 30);
		labeldestination.setBounds(250, 160, 150, 30);
		
		
		
		buttons.add(stopBtn);
		buttons.add(mymenubar);
		buttons.add(labelType);
		buttons.add(labelName);
		buttons.add(labeldestination);

		infoPanel.add(txtAreaJp);
		
		
		setLayout(new GridLayout(3, 1));
		 add(buttons);
		add(scrollPane);
		
		add(infoPanel);
		
		
		
		setVisible(true);
		setSize(900, 600);
		
		/*startBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				CompletableFuture.runAsync(() -> {
					sniffer.start();
				});
			}
		});
		*/
		capture.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				// TODO Auto-generated method stub
				CompletableFuture.runAsync(() -> {
					sniffer.start();
				});
			}
		});
		
		stopBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				sniffer.stop();
			}
		});
		
		
		
		
		DefaultMutableTreeNode root = new DefaultMutableTreeNode("INFO");
		
		
        JTree tree = new JTree(root);
       
        
		DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
		
		treeJp.add(tree);
        
       
        DefaultMutableTreeNode NETWORK_LAYER= new DefaultMutableTreeNode("NETWORK_LAYER");
        
        DefaultMutableTreeNode TRANSPORT_LAYER= new DefaultMutableTreeNode("TRANSPORT_LAYER");
       
        
        DefaultMutableTreeNode arp= new DefaultMutableTreeNode("ARP");
        DefaultMutableTreeNode ip= new DefaultMutableTreeNode("IPV4");
        DefaultMutableTreeNode icmp= new DefaultMutableTreeNode("ICMP");
        DefaultMutableTreeNode udp= new DefaultMutableTreeNode("UDP");
        DefaultMutableTreeNode tcp= new DefaultMutableTreeNode("TCP");
       //udp
        DefaultMutableTreeNode SrcPortudp= new DefaultMutableTreeNode("Source Port");
        DefaultMutableTreeNode destPortudp= new DefaultMutableTreeNode("Destination Port");
        DefaultMutableTreeNode packlengudp= new DefaultMutableTreeNode("Packet Length");
        //tcp
        
		DefaultMutableTreeNode SrcPorttcp= new DefaultMutableTreeNode("Source Port");
        DefaultMutableTreeNode destPorttcp= new DefaultMutableTreeNode("Destination Port");
        DefaultMutableTreeNode seqnumbtcp= new DefaultMutableTreeNode("Sequence Number");
        DefaultMutableTreeNode asknumbtcp= new DefaultMutableTreeNode("Ack Number");
        DefaultMutableTreeNode urgfltcp= new DefaultMutableTreeNode("URG Flag");
        DefaultMutableTreeNode ackfltcp= new DefaultMutableTreeNode("ACK Flag");
        DefaultMutableTreeNode pshfltcp= new DefaultMutableTreeNode("PSH Flag");
        DefaultMutableTreeNode rstflg= new DefaultMutableTreeNode("RST Flag");
        DefaultMutableTreeNode synfltcp= new DefaultMutableTreeNode("SYN Flag");
        DefaultMutableTreeNode finfltcp= new DefaultMutableTreeNode("FIN Flag");
        DefaultMutableTreeNode windsizetcp= new DefaultMutableTreeNode("Window Size");
        //icmp
        
		
		 DefaultMutableTreeNode sourceicmp= new DefaultMutableTreeNode("source ip");
		 DefaultMutableTreeNode desticmp= new DefaultMutableTreeNode("destination ip");
        DefaultMutableTreeNode codeicmp= new DefaultMutableTreeNode("Code");
        DefaultMutableTreeNode idicmp= new DefaultMutableTreeNode("ID");
        DefaultMutableTreeNode sequenceicmp= new DefaultMutableTreeNode("Sequence");
        DefaultMutableTreeNode redictadrsicmp= new DefaultMutableTreeNode("Redirect Address");
        DefaultMutableTreeNode dataicmp= new DefaultMutableTreeNode("data");
        //arp
        DefaultMutableTreeNode senderp= new DefaultMutableTreeNode("Sender Protocol Address");
        DefaultMutableTreeNode senderh= new DefaultMutableTreeNode("Sender Hardware Address");
        DefaultMutableTreeNode targetp= new DefaultMutableTreeNode("Target Protocol Address");
        DefaultMutableTreeNode targeth= new DefaultMutableTreeNode("Target Hardware Address");
        //ipv4
        DefaultMutableTreeNode vs= new DefaultMutableTreeNode("Version");
        DefaultMutableTreeNode shn= new DefaultMutableTreeNode("Source Host Name");
        DefaultMutableTreeNode dhn= new DefaultMutableTreeNode("Destination Host Name");
        DefaultMutableTreeNode pt= new DefaultMutableTreeNode("TOS: Priority");
        DefaultMutableTreeNode lg= new DefaultMutableTreeNode("Length");
        DefaultMutableTreeNode id= new DefaultMutableTreeNode("Identification");
        DefaultMutableTreeNode df= new DefaultMutableTreeNode("Fragment: Don't Fragment");
        DefaultMutableTreeNode mf= new DefaultMutableTreeNode("Fragment: More Fragment");
        DefaultMutableTreeNode fo= new DefaultMutableTreeNode("Fragment Offset");
        DefaultMutableTreeNode tol= new DefaultMutableTreeNode("Time To Live");
        DefaultMutableTreeNode prt= new DefaultMutableTreeNode("Protocol");
        DefaultMutableTreeNode si= new DefaultMutableTreeNode("Source IP");
        DefaultMutableTreeNode di= new DefaultMutableTreeNode("Destination IP");
      
      
        root.add(NETWORK_LAYER);
        
        root.add(TRANSPORT_LAYER);
        
        NETWORK_LAYER.add(arp);
        NETWORK_LAYER.add(ip);
        TRANSPORT_LAYER.add(icmp);
        TRANSPORT_LAYER.add(udp);
        TRANSPORT_LAYER.add(tcp);
        //udp
        udp.add(SrcPortudp);
        udp.add(destPortudp);
        udp.add(packlengudp);
        //tcp
        tcp.add(SrcPorttcp);
        tcp.add(destPorttcp);
        tcp.add(seqnumbtcp);
        tcp.add(asknumbtcp);
        tcp.add(urgfltcp);
        tcp.add(ackfltcp);
        tcp.add(pshfltcp);
        tcp.add(rstflg);
        tcp.add(synfltcp);
        tcp.add(finfltcp);
        tcp.add(windsizetcp);
        //arp
        arp.add(senderp);
        arp.add(senderh);
        arp.add(targetp);
        arp.add(targeth);
        //ip
        ip.add(vs);
        ip.add(shn);
        ip.add(dhn);
        ip.add(pt);
        ip.add(lg);
        ip.add(id);
        ip.add(df);
        ip.add(mf);
        ip.add(fo);
        ip.add(tol);
        ip.add(prt);
        ip.add(si);
        ip.add(di);
        
        //icmp
       
        icmp.add(sourceicmp);
        icmp.add(desticmp);
        icmp.add(codeicmp);
        icmp.add(idicmp);
        icmp.add(sequenceicmp);
        icmp.add(redictadrsicmp);
        icmp.add(dataicmp);
        
        
        model.reload();
       
        treeJp.setVisible(false);
        
		list.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				PacketInfo info = list.getSelectedValue();
				if(info == null) return;
				//System.out.println(info);		
		        treeJp.setVisible(true);
				txtAreaJp.setVisible(true);
			}
		});
		
		
		tree.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// TODO Auto-generated method stub
				TreePath[] paths = tree.getSelectionPaths();
				String choice = tree.getLastSelectedPathComponent().toString();
				PacketInfo info = list.getSelectedValue();
				
				if(choice.equals("Ip Source")) {
					
					txtArea.setText(info.srcIp);
				} else if(choice.equals("Ip Destination")) {
					
					txtArea.setText(info.destIp);
				} else if(choice.equals("Data")) {
					
					txtArea.setText(info.getData());
				}else if(choice.equals("hardware")) {
					
					txtArea.setText(info.hardware);
				}else if(choice.equals("HTTP")) {
					
					txtArea.setText(info.hardware);
				}
				else if(choice.equals("Ack Number")) {
					
					txtArea.setText(info.ack+"");
					
				}
				//icmp
				else if(choice.equals("source ip")) {
					
					txtArea.setText(info.srcIp+"");
					
				}
				else if(choice.equals("destination ip")) {
					
					txtArea.setText(info.destIp+"");
					
				}
				else if(choice.equals("Code")) {
					
					txtArea.setText(info.cd+"");
					
				}
				else if(choice.equals("ID")) {
					
					txtArea.setText(info.idd+"");
					
				}
				else if(choice.equals("Sequence")) {
					
					txtArea.setText(info.sequ+"");
					
				}
				else if(choice.equals("Redirect Address")) {
					
					txtArea.setText(info.redirect+"");
					
				}
				else if(choice.equals("data")) {
					
					txtArea.setText(info.data+"");
					
				}
				//udp
				else if(choice.equals("Source Port")) {
					
					txtArea.setText(info.srcPort+"");
					
				}
				else if(choice.equals("Destination Port")) {
					
					txtArea.setText(info.destPort+"");
					
				}
				else if(choice.equals("Packet Length")) {
					
					txtArea.setText(info.lgt+"");
					
				}
				//tcp
				else if(choice.equals("Source Port")) {
					//System.out.println("HTTP");
					txtArea.setText(info.srcPort+"");
					
				}
				else if(choice.equals("Destination Port")) {
					
					txtArea.setText(info.destPort+"");
					
				}
				else if(choice.equals("Sequence Number")) {
					
					txtArea.setText(info.seq+"");
					
				}
				else if(choice.equals("Ack Number")) {
					
					txtArea.setText(info.acknum+"");
					
				}
				else if(choice.equals("URG Flag")) {
					
					txtArea.setText(info.ug+"");
					
				}
				else if(choice.equals("ACK Flag")) {
					
					txtArea.setText(info.ack+"");
					
				}
				else if(choice.equals("PSH Flag")) {
					
					txtArea.setText(info.psh+"");
					
				}
				else if(choice.equals("RST Flag")) {
					
					txtArea.setText(info.rt+"");
					
				}
				else if(choice.equals("SYN Flag")) {
					
					txtArea.setText(info.sy+"");
					
				}
				else if(choice.equals("FIN Flag")) {
					
					txtArea.setText(info.fn+"");
					
				}
				else if(choice.equals("Window Size")) {
					
					txtArea.setText(info.wd+"");
					
				}
				
				//http
				//arp
				else if(choice.equals("Sender Protocol Address")) {
					
					txtArea.setText(info.getsender+"");
					
				}
				else if(choice.equals("Sender Hardware Address")) {
					
					txtArea.setText(info.sender+"");
					
				}
				else if(choice.equals("Target Protocol Address")) {
					
					txtArea.setText(info.targetprotocol+"");
					
				}
				else if(choice.equals("Target Hardware Address")) {
					
					txtArea.setText(info.gettarget+"");
					
				}
				
				//ipv4
				else if(choice.equals("Version")) {
					
					txtArea.setText(info.version+"");
					
				}
				else if(choice.equals("TOS: Priority")) {
					
					txtArea.setText(info.prt+"");
					
				}
				else if(choice.equals("Length")) {
					
					txtArea.setText(info.lg+"");
					
				}
				else if(choice.equals("Identification")) {
					
					txtArea.setText(info.idt+"");
					
				}
				else if(choice.equals("Fragment: Don't Fragment")) {
					
					txtArea.setText(info.df+"");
					
				}
				else if(choice.equals("Fragment: More Fragment")) {
					
					txtArea.setText(info.mf+"");
					
				}
				else if(choice.equals("Fragment Offset")) {
					
					txtArea.setText(info.of+"");
					
				}
				else if(choice.equals("Time To Live")) {
					
					txtArea.setText(info.lt+"");
					
				}
				else if(choice.equals("Protocol")) {
					
					txtArea.setText(info.prct+"");
					
				}
				else if(choice.equals("Source IP")) {
					
					txtArea.setText(info.srcIp+"");
					
				}
				else if(choice.equals("Destination IP")) {
					
					txtArea.setText(info.destIp+"");
					
				}
				else if(choice.equals("Source Host Name")) {
					
					txtArea.setText(info.srchost+"");
					
				}
				else if(choice.equals("Destination Host Name")) {
					
					txtArea.setText(info.dschost+"");
					
				}
				
			}
		});
		
		new ListenersForAction(this);
	}


	
	
}
