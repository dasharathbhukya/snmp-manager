package com.comtech.snmp.v3;


import java.io.IOException;
import java.net.UnknownHostException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SNMPManager {

	Snmp snmp = null;
	String address = null;

	/**
	 * Constructor
	 * @param add
	 */
	public SNMPManager(String add)
	{
		address = add;
	}

	public static void main(String[] args) throws IOException {
		/**
		 * Port 161 is used for Read and Other operations
		 * Port 162 is used for the trap generation
		 */
		SNMPManager client = new SNMPManager("udp:127.0.0.1/1024");
		client.start();
		/**
		 * OID - .1.3.6.1.2.1.1.1.0 => SysDec
		 * OID - .1.3.6.1.2.1.1.5.0 => SysName
		 * => MIB explorer will be usefull here, as discussed in previous article
		 */
		String sysDescr = client.getAsString(new OID(".1.3.6.1.2.1.1.1.0"));
		System.out.println(".1.3.6.1.2.1.1.1.0 == "+sysDescr);
		String sysDescr1 = client.getAsString(new OID(".1.3.6.1.2.1.1.5.0")); 
		System.out.println(".1.3.6.1.2.1.1.5.0 == "+sysDescr1);
		String sysDescr2 = client.getAsString(new OID(".1.3.6.1.2.1.1.6.0")); 
		System.out.println(".1.3.6.1.2.1.1.6.0 == "+sysDescr2);
		sysDescr2 = client.getAsString(new OID(".1.3.6.1.2.1.2.2")); 
		System.out.println(".1.3.6.1.2.1.2.2 == "+sysDescr2);
		sysDescr2 = client.getAsString(new OID(".1.3.6.1.2.1.1.9.1.3.2")); 
		System.out.println(".1.3.6.1.2.1.1.9.1.3.2 == "+sysDescr2);
		client.getset(new OID[] { new OID("1.3.6.1.2.1.1.6.0")});
		
//		String []oids = {".1.3.6.1.2.1.1.9.1.3.1"};
//		client.set(oids);

		sysDescr2 = client.getAsString(new OID(".1.3.6.1.2.1.1.6.0"));
		System.out.println(".1.3.6.1.2.1.1.6.0 == "+sysDescr2);
		
		//========================================
		
		System.out.println("java :::::::::::::");
		
//		SNMPManager client2 = new SNMPManager("udp:127.0.0.1/161");
//		client2.start();
		/**
		 * OID - .1.3.6.1.2.1.1.1.0 => SysDec
		 * OID - .1.3.6.1.2.1.1.5.0 => SysName
		 * => MIB explorer will be usefull here, as discussed in previous article
		 */
//		String sysDesc2 = client2.getAsString(new OID(".1.3.6.1.4.1.53427.1.4.2"));
//		System.out.println("agent 2 :::: "+sysDesc2);
//		
//		String sysDesc3 = client2.getAsStringForSetter(new OID(".1.3.6.1.4.1.53427.1.4.2"));
//				
//		System.out.println("agent 2 New value:::: "+ sysDesc3);
//	
//		String sysDes3 = client2.getAsString(new OID(".1.3.6.1.4.1.53427.1.4.2"));
//		System.out.println("agent 2 :::: "+sysDes3);
		
	}

	/**
	 * Start the Snmp session. If you forget the listen() method you will not
	 * get any answers because the communication is asynchronous
	 * and the listen() method listens for answers.
	 * @throws IOException
	 */
	private void start() throws IOException {
		TransportMapping transport = new DefaultUdpTransportMapping();
		snmp = new Snmp(transport);
		// Do not forget this line!
		transport.listen();
	}

	/**
	 * Method which takes a single OID and returns the response from the agent as a String.
	 * @param oid
	 * @return
	 * @throws IOException
	 */
	public String getAsString(OID oid) throws IOException {
		ResponseEvent event = get(new OID[] { oid });
		return event.getResponse().get(0).getVariable().toString();
	}

	public String getAsStringForSetter(OID oid) throws IOException {
		ResponseEvent event = getset(new OID[] { oid });
		return event.getResponse().get(0).getVariable().toString();
	}
	
	/**
	 * This method is capable of handling multiple OIDs
	 * @param oids
	 * @return
	 * @throws IOException
	 */
	public ResponseEvent get(OID oids[]) throws IOException {
		PDU pdu = new PDU();
		for (OID oid : oids) {
			pdu.add(new VariableBinding(oid));
		}
		pdu.setType(PDU.GET);
		
		ResponseEvent event = snmp.send(pdu, getTarget(), null);
		
		if(event != null) {
			return event;
		}
		throw new RuntimeException("GET timed out");
	}
	
	public ResponseEvent getset(OID oids[]) throws IOException {
		PDU pdu = new PDU();
//		for (OID oid : oids) {
//			pdu.add(new VariableBinding(oid, new Integer32(100)));
//		}
		
		pdu.add(new VariableBinding(new OID(oids[0]), new OctetString("This is test.........")));
		
		pdu.setType(PDU.SET);
		System.out.println("PDU: " + pdu);
		
		ResponseEvent event = snmp.set(pdu, getTarget());
		
	    System.out.println("response " + event.toString());

		System.out.println("<>>>>>><>:::"+event.getResponse().get(0).getVariable().toString());
		if(event != null) {
			return event;
		}
		throw new RuntimeException("GET timed out");
	}

	public String set(OID oid) throws IOException {
		PDU pdu = new PDU();
		
		pdu.add(new VariableBinding(new OID(oid), new Integer32(100)));
		List<VariableBinding> vbs = new ArrayList<VariableBinding>();
		vbs.add(new VariableBinding(new OID(oid), new Integer32(100)));
		
		pdu.setVariableBindings(vbs);
		pdu.setType(PDU.RESPONSE);
		
//		CommandResponderEvent<Address> addr = snmp.send(pdu, null) new SNMPManager(address); 
		snmp.send(pdu, getTarget());
		return "";
//		System.out.println(event.toString());
//		if(event != null) {
//			
//			return event.getResponse().get(0).getVariable().toString();//event;
//		}
//		throw new RuntimeException("GET timed out");
	}
	/**
	 * This method returns a Target, which contains information about
	 * where the data should be fetched and how.
	 * @return
	 */
	private Target getTarget() {
		Address targetAddress = GenericAddress.parse(address);
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		target.setAddress(targetAddress);
		target.setRetries(2);
		target.setTimeout(1500);
		target.setVersion(SnmpConstants.version2c);
		return target;
	}

	
	public void set(String []oids){
		  PDU pdu = new PDU();
		  for (int i = 1; i < oids.length; i+=2){
		      pdu.add(new VariableBinding(new OID(oids[i]), new OctetString("This is test.........")));	
		    }
		//   OID oidn = new OID(oid);
		//   Variable var = new OctetString(value);
		//   VariableBinding varBind = new VariableBinding(oidn, var);
		//   pdu.add(varBind);
		  pdu.setType(PDU.SET);
		  CommunityTarget target = new CommunityTarget();
		  target.setCommunity(new OctetString("private"));
		  target.setVersion(SnmpConstants.version2c);
		  Address targetAddress = GenericAddress.parse("udp:127.0.0.1/1024");
		  target.setAddress(targetAddress);
		  target.setRetries(2);
		  target.setTimeout(1000);
		try{
		DefaultUdpTransportMapping transport = new DefaultUdpTransportMapping();
		transport.listen();
		Snmp snmp = new Snmp(transport);	
		long t1 = System.currentTimeMillis();
		    System.out.println("SENDING: "+t1);
		System.out.println("PDU: " + pdu);
		    ResponseEvent responseEvent = snmp.set(pdu, getTarget());
		    long t2=System.currentTimeMillis();
		    System.out.println("SENT: "+t2);
		    System.out.println("ELAPSED: "+(t2-t1));
		    System.out.println("response " + responseEvent.toString());

		PDU responsePDU = responseEvent.getResponse();
		if (responsePDU == null){
		  System.out.println("Response is null. Check RequestHandlerImpl");
		  System.out.println("Request timed out.");
		}
		else {
		  System.out.println("Received response "+responsePDU);
		    }
		        System.out.println("Peer Address: "+responseEvent.getPeerAddress());
		} catch (UnknownHostException e1) {
		  // TODO Auto-generated catch block
		  e1.printStackTrace();
		} catch (IOException e1) {
		  // TODO Auto-generated catch block
		  e1.printStackTrace();
		} catch (Exception e) {
		  System.out.println("Some Other exception!!");
		}

		}
	
}