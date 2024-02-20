package com.comtech.snmp.v3;

import java.io.IOException;

import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.ThreadPool;

public class SNMPv3Simulator2 {

    private Snmp snmp;
    private ThreadPool threadPool;

    public SNMPv3Simulator2() throws IOException {
        threadPool = ThreadPool.create("DispatcherPool", 10);
        MessageDispatcherImpl dispatcher = new MessageDispatcherImpl();
        TransportMapping<? extends Address> transport;

        // UDP
        transport = new DefaultUdpTransportMapping();
        // TCP
        //transport = new DefaultTcpTransportMapping();
        snmp = new Snmp(dispatcher, transport);
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
        MPv3 mpv3 = new MPv3(usm);
        snmp.getMessageDispatcher().addMessageProcessingModel(mpv3);
    }

    public void start() throws IOException {
        snmp.listen();
    }

    public void stop() throws IOException {
        snmp.close();
    }

    public void sendTrap(String agentAddress, String community, String trapOid, String trapMessage) throws IOException {
        Address targetAddress = GenericAddress.parse(agentAddress);
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString(community));
        target.setAddress(targetAddress);
        target.setVersion(org.snmp4j.mp.SnmpConstants.version3);

        VariableBinding[] vbs = new VariableBinding[1];
        vbs[0] = new VariableBinding(new org.snmp4j.smi.OID(trapOid), new OctetString(trapMessage));

        org.snmp4j.PDU pdu = new org.snmp4j.PDU();
        pdu.setType(org.snmp4j.PDU.NOTIFICATION);
        for (VariableBinding vb : vbs) {
            pdu.add(vb);
        }
        ScopedPDU pdu2 = new ScopedPDU();
        pdu2.setType(org.snmp4j.PDU.NOTIFICATION);
        for (VariableBinding vb : vbs) {
//            pdu.add(vb);
            pdu2.add(vb);
        }
        
        snmp.send(pdu2, getTarget());
    }
    
    /**
	 * This method returns a Target, which contains information about
	 * where the data should be fetched and how.
	 * @return
	 */
	private Target getTarget() {
		Address targetAddress = GenericAddress.parse("udp:127.0.0.1/1024");
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString("public"));
		target.setAddress(targetAddress);
		target.setRetries(2);
		target.setTimeout(1500);
		target.setVersion(SnmpConstants.version1);
		return target;
	}

//    public static void main(String[] args) {
//        try {
//            SNMPv3Simulator2 simulator = new SNMPv3Simulator2();
//            simulator.start();
//
//            // Simulate sending a trap
//            simulator.sendTrap("udp:127.0.0.1/162", "public", "1.3.6.1.2.1.1.1.0", "Device overheating");
//
//            // Do other operations...
//
//            simulator.stop();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
	
	public static void main(String[] args) throws Exception {
        TransportMapping transport = new DefaultUdpTransportMapping();
        Snmp snmp = new Snmp(transport);

        OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
        
        UsmUser usmUser = new UsmUser(new OctetString("simulator"),
	    	    AuthMD5.ID, new OctetString("auctoritas"),
	    	    PrivDES.ID, new OctetString("privatus"));

	    usm.addUser(usmUser);
	    
        SecurityModels.getInstance().addSecurityModel(usm);

        OctetString securityName = new OctetString("simulator");
        OID authProtocol = AuthMD5.ID;
        OID privProtocol = PrivDES.ID;
        OctetString authPassphrase = new OctetString("auctoritas");
        OctetString privPassphrase = new OctetString("privatus");

        snmp.getUSM().addUser(securityName, new UsmUser(securityName, authProtocol, authPassphrase, privProtocol, privPassphrase));
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

        UserTarget target = new UserTarget();
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(securityName);

        target.setAddress(GenericAddress.parse(String.format("udp:%s/%s", "127.0.0.1", "1024")));
        target.setVersion(SnmpConstants.version3);
        target.setRetries(2);
        target.setTimeout(10000);
        transport.listen();

        PDU pdu = new ScopedPDU();
        pdu.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.9.1.3.1")));
        pdu.setType(PDU.GET);
        ResponseEvent event = snmp.send(pdu, target);
        System.out.println("this is test>>>>>>>>>>>>>"+ event);
        if (event != null) {
            PDU pdu2 = event.getResponse();
            System.out.println(pdu2.get(0).getVariable().toString());
            if (pdu2.getErrorStatus() == PDU.noError) {
                System.out.println("SNMPv3 GET Successful!");
            } else {
                System.out.println("SNMPv3 GET Unsuccessful.");
            }
        } else {
            System.out.println("SNMP get unsuccessful.");
        }

	}
}
