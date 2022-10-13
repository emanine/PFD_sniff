package sniff;

import javax.swing.AbstractListModel;
import java.util.*;

public class PacketInfoModel extends AbstractListModel{
	public Vector<PacketInfo> packetVector = new Vector<PacketInfo>();

	@Override
	public Object getElementAt(int index) {
		// TODO Auto-generated method stub
		try {
			return packetVector.get(index);
		} catch(Exception e) {
			return null;
		}}

	@Override
	public int getSize() {
		// TODO Auto-generated method stub
		return packetVector.size();   }
	
	public void add(PacketInfo info) {
		packetVector.add(info);
		int size = this.getSize();
		fireIntervalAdded(this, size - 1, size);
		}
	  
	public void remove(int index) {
		packetVector.remove(index);
		fireIntervalRemoved(this, index, index + 1);   }
}
