package com.comtech.snmp.v3;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class SNMPManager {

    private Snmp snmp;

    public SNMPManager(String ipAddress) throws IOException {
        // Create TransportMapping and Listen
        TransportMapping<? extends Address> transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        transport.listen();

        // Create Target Address object
        Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/1024");
        Target target = new CommunityTarget(targetAddress, new OctetString("public"));

        // Retries and Timeout
        ((CommunityTarget) target).setRetries(2);
        ((CommunityTarget) target).setTimeout(1500);
        ((CommunityTarget) target).setVersion(SnmpConstants.version2c);
    }

    public void updateSNMPValue(String oid, String newValue) throws IOException {
        // Create PDU
        PDU pdu = new PDU();
        pdu.setType(PDU.SET);
        pdu.add(new VariableBinding(new OID(oid), new OctetString(newValue)));

        // Send PDU and get response
//        ResponseEvent response = snmp.send(pdu, getTarget(), null);
        ResponseEvent response = snmp.set(pdu, getTarget());

        // Process Response
        if (response != null && response.getResponse() != null) {
            System.out.println("Response received: " + response.getResponse().toString());
        } else {
            System.out.println("No response received.");
        }
    }

    private Target getTarget() {
        // Address of Target
        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/1024");

        // Community Target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);

        return target;
    }

    public static void main(String[] args) {
        try {
            SNMPManager manager = new SNMPManager("127.0.0.1");
            manager.updateSNMPValue("1.3.6.1.2.1.1.6.0", "New Value");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

