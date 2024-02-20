package com.comtech.snmp.v3;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class OIDEntryV3 {

	// snmpV3 preset: user name, password, delay... etc
	public static int	 pduOutlet_num  	= 8;
	public static String securityName       = "simulator";
	public static String authPassphrase     = "auctoritas";
	public static String privPassphrase     = "privatus";
	public static String single_oid 	    = "00000";
	public static String setNum		   		= "3";
	public static int    requestDelay 	   	= 3;    
	public static int    delayOn 	   	    = 1;
	public static int    delayOff 	   	    = 2;   
//	public static String init_contextName	= "0886e1397d572377c17c15036a1e6c66 or variation/writecache";
	public static String init_contextName	= "0886e1397d572377c17c15036a1e6c66";
	
//	 SNMPv3 Context Name: 0886e1397d572377c17c15036a1e6c66 or variation/writecache
//	  --- SNMPv3 USM configuration
//	  SNMPv3 USM SecurityName: simulator
//	  SNMPv3 USM authentication key: auctoritas, authentication protocol: MD5
//	  SNMPv3 USM encryption (privacy) key: privatus, encryption protocol: DES
//	  Maximum number of variable bindings in SNMP response: 64


	public UsmUser usmUser = new UsmUser(new OctetString(securityName),
			AuthMD5.ID, new OctetString(authPassphrase),
			PrivDES.ID, new OctetString(privPassphrase));

	public Snmp snmp;	
	public USM usm;
	public static Target<Address> userTarget  = new UserTarget<Address>();


	private static boolean	snmpv3SetCommSetup = false; 
	private static boolean	snmpv3GetCommSetup = false; 


	private String udpAddressInfo;
	private int 		timeIndex = requestDelay;
	private String 		contextName = init_contextName;
	private String [] 	oids;


//	private ScopedPDU setScopedPDU, getScopedPDU;
	private ScopedPDU setScopedPDU, getScopedPDU;
	private int attempt_num = 1; // how many time the for loop to do snmpV3 comm






	//constructor of OIDEntryV3 input
	public OIDEntryV3(String udpAddressInfo, int timeIndex, String contextName, String... oids) 
	{
		this.udpAddressInfo	= 	udpAddressInfo;
	    this.timeIndex 	 	= 	timeIndex;
	    this.contextName 	= 	contextName;
	    this.oids			= 	oids;
	}


	public OIDEntryV3(String udpAddressInfo, String... oids) 
	{
		this.udpAddressInfo	= 	udpAddressInfo;
	    this.oids			= 	oids;
	}


//	private static Logger logger = LoggerFactory.getLogger(OIDEntryV3.class);




	// initialize SNMPV3 communication 
	public void initSnmpV3() throws IOException {
		
		TransportMapping transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
		
//	    snmp = new Snmp();
	    snmp.getMessageDispatcher().addCommandResponder(new CommandResponder() {
	        //@Override
	        public <A extends Address> void processPdu(CommandResponderEvent<A> commandResponderEvent) {
	        	System.out.println("processPdu::::::::::::::");
	        }
	    });
	    // Very important to add snmp as command responder which will finally process the PDU:
	    snmp.getMessageDispatcher().addCommandResponder(snmp);


	    snmp.addTransportMapping(new DefaultUdpTransportMapping(new UdpAddress(0)));
	    snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());
	   
	    SecurityProtocols.getInstance().addDefaultProtocols();

	    SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
	    SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());

	    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivDES());
	    SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
	    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES128());
	    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
	    SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());
	    

	    OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());        
	    usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
	    usmUser = new UsmUser(new OctetString(securityName),
	    	    AuthMD5.ID, new OctetString(authPassphrase),
	    	    PrivDES.ID, new OctetString(privPassphrase));

	    usm.addUser(usmUser);
	    	    
	    SecurityModels.getInstance().addSecurityModel(usm); 
	    
//	    snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm.getLocalEngineID().getValue()));
	    snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

//	    snmp.listen();
	    transport.listen();
//	    usm.addUser(usmUser);
	    

		Address targetAddress = GenericAddress.parse(udpAddressInfo);
	    userTarget.setAddress(targetAddress);
	    userTarget.setVersion(SnmpConstants.version3);
	    userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
	    userTarget.setSecurityName(usmUser.getSecurityName());
	    

	    userTarget.setRetries(3);
	    userTarget.setTimeout(500);
	    System.out.println("end of initSnmpV3:::::::::");

	      		 
	}


	//SCOPED PDU for SNMP GET
	public ScopedPDU getScopedPDU(){
		
	    List<VariableBinding> oidList = new ArrayList<VariableBinding>(oids.length);
		
		System.out.println("start of the getScopedPDU ::::::::::: " + oids.toString());
		
		// only need to assign ScopedPDU once
		if(getScopedPDU == null){

		    getScopedPDU = new ScopedPDU();
	        
			for (String objectID : oids){	
//				oidList.add(new VariableBinding(new OID(objectID),  new OctetString("This is test.........")));
				oidList.add(new VariableBinding(new OID(objectID)));
			}
			
//			PDU pdu = new PDU();
//			for (OID oid : oids) {
//				pdu.add(new VariableBinding(oid));
//			}
//			pdu.setType(PDU.GET);
		    
			getScopedPDU.addAll(oidList);
	        getScopedPDU.setType(PDU.GET);	 
//	        getScopedPDU.setContextEngineID(new OctetString("0x80004fb8054953494e2d4c502d3231335030d140"));
//	        getScopedPDU.setContextName(new OctetString(this.contextName));
		}
		System.out.println("end of the getScopedPDU ::::::::::: " + getScopedPDU.toString());
		return getScopedPDU;
	}

	// ScopedPDU for snmpV3 SET
	public ScopedPDU setScopedPDU(){
		
	    List<VariableBinding> oidList = new ArrayList<VariableBinding>(oids.length);
	   
		// only need to assign ScopedPDU once
		if(setScopedPDU == null){
			


		    setScopedPDU = new ScopedPDU();
		    
			for (String objectID : oids){
				oidList.add(new VariableBinding( new OID(objectID), new Integer32(timeIndex) ));            
			}
			setScopedPDU.addAll(oidList);
			
			//set port name etc... 
	        setScopedPDU.setContextName(new OctetString(contextName));
	        setScopedPDU.setType(PDU.SET);
		}
	    
		return setScopedPDU;
	}    

	private String getVal;


	public String getSnmpV3Req()throws IOException {

		System.out.println("start of the getSnmpV3Req:::::::::::::::::");
		if(!snmpv3GetCommSetup)
		{
			try
			{
				initSnmpV3();
				//snmpv3GetCommSetup = true;
			}
			catch(IOException e)
			{
				System.err.println("SNMPV3 GET initial comm setup fail");
				throw e;
			}
		}
		
		// initialize v3 get scopedPDU
		getScopedPDU();
		


	    // A ResponseListener object is created to handle the response from the SNMP agent. 
	    // The onResponse method is implemented to extract the variable bindings from the response 
	    // and print the values to the console.
		
		// attempts for snmpv3 get
		for (int i = 0; i < attempt_num ; i++) {
			System.out.println("attempts for snmpv3 get:::::::::::::attempt_num::"+ attempt_num);
			getVal = "Waiting for get value";
			
			try{
	    		System.out.println("*** for loop i = "+i);
	    		
		        ResponseListener responseListener = new ResponseListener() 
		        {
		            //@Override
		            
		            // The synchronized block is used to ensure that the responseListener object is not notified 
		            // before it has finished processing the response.
		            public synchronized  <A extends Address> void onResponse(ResponseEvent<A> responseEvent) 
		            {
		        		// cancel the pending SNMP request that was associated with the ResponseEvent object responseEvent, 
		        		// and informs the object (this) that was listening for the response that the request has been cancelled
		                snmp.cancel(responseEvent.getRequest(), this);
		                // Process response here: gotta format the output values nicely
		                List<? extends VariableBinding> vBindings = responseEvent.getResponse().getVariableBindings();  
		                
		        		System.out.println("----- variable Binding = "+vBindings);
		                
		                for (VariableBinding vb:vBindings) 
		                {
		                	if (vb.getVariable() != null) 
		                	{
		                		getVal = vb.getVariable().toString();
		                		System.out.println("----- V3 get value = "+vb.getVariable().toString());
		                		
		                	}
		                	else 
		                	{
		                		//getSNMPCommError = true;
		                		
		                		if(responseEvent.getError() != null) 
		                		{
		                			System.err.println("Error: "+responseEvent.getError());
		                		}
		                		else 
		                		{
		                			System.err.println("Timed out.");
		                		}
		                	}
		                }
		                notify();
		                
		            }
		        };
		        
		        synchronized (responseListener) 
		        {
		        	System.out.println("synchronized .... response listener........");
		        	// send snmpv3 get request, using responseListener to catch the response
		            snmp.get(getScopedPDU, userTarget, null, responseListener);
//		            snmp.get(getScopedPDU, userTarget);
//		            snmp.get(getScopedPDU, userTarget, null, responseListener);
		           
			        
					System.out.println("~~~ ResponseListener = "+responseListener);
		            
		            try{
		            	responseListener.wait(500000);
		            	
		            }
		            catch(InterruptedException eee) 
		            {	
		            	eee.printStackTrace();
		            	
		            }
		            
		            
		        }
				
				
			}
			
			catch (IOException ioe) 
			{
				ioe.printStackTrace();
				System.err.println("OIDEntryV3.java: IOException occurred during SNMPv3 GET Communication: " + ioe.getMessage());
				try {Thread.sleep(2000);} 
				catch (InterruptedException e1) 
				{	
					e1.printStackTrace();
					System.err.println("OIDEntryV3.java: InterruptedException occurred during SNMPv3 GET Communication: " + e1.getMessage());
					throw ioe;
				}
			}
		}
		
		/*
		if(getSNMPCommError)
		{
			e.printStackTrace();
			throw e;
		}*/
		System.out.println("end of the getSnmpV3Req:::::::::::::::::");
		return getVal;
	}


	// set snmpV3 requests
	public void setSnmpV3Req() throws IOException 
	{
		//IOException e = null;
		//setSNMPCommError = false;
		
		if(!snmpv3SetCommSetup)
		{
			try
			{
				initSnmpV3();
				//snmpv3SetCommSetup = true;
			}
			catch(IOException e)
			{
				System.err.println("SNMPV3 SET initial comm setup fail");
				throw e;
			}
		}
		
		
		
		// initialize v3 set scopedPDU
		setScopedPDU();


		// attempts for snmpv3 set
		for (int i = 0; i < attempt_num ; i++) 
		{
			System.out.println("***** setset ");
			try 
			{
		        ResponseEvent<Address> responseEvent = snmp.send(setScopedPDU, userTarget);
		        
		        PDU response = responseEvent != null ? responseEvent.getResponse() : null;
		        List<? extends VariableBinding> response_msg = response != null ? response.getVariableBindings() : null;
		        			
		        			
		        if (response != null)
		        {
		        	if (response.getErrorStatus() == PDU.noError) 
		        	{
		        		//System.out.println("***** set req = " +response_msg);
		        		System.err.println("***** OID command = " +response_msg.get(0).getOid());
		        		System.err.println("***** set command time = " +response_msg.get(0).getVariable());				
		        	} 
		        	else
		        	{			
		        		
		        		System.err.println("ErrorStatusText:" + response.getErrorStatusText());
		        		System.err.println("ErrorIndex:" + response.getErrorIndex());
		        		System.err.println("ErrorStatus:" + response.getErrorStatus());
		        	}
		        }

			}
			
			catch (IOException ioe) 
			{
				ioe.printStackTrace();
				System.err.println("OIDEntryV3.java: IOException occurred during SNMPv3 SET Communication: " + ioe.getMessage());
				try {Thread.sleep(2000);} 
				catch (InterruptedException e1) 
				{	
					e1.printStackTrace();
					System.err.println("OIDEntryV3.java: InterruptedException occurred during SNMPv3 SET Communication: " + e1.getMessage());
					throw ioe;
				}
			}
		}
		
		/*if(setSNMPCommError)
		{
			catch(IOException e) 
			{
				System.err.println("OIDEntryV3.java: IOException occurred during SNMPv3 SET Communication: " + e.getMessage());
				throw e;
			}
			
		}*/
		
	}
	
	public static void main(String[] args) throws IOException {
		
		String[] oid = new String[] {".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.25.4.2.1.2"};
		
		OIDEntryV3 v3 = new OIDEntryV3("localhost/1024", oid);
//		v3.initSnmpV3();
//		v3.setSnmpV3Req();
//		Thread t = new Thread();
//		try {
//			t.sleep(10000);
//		} catch (InterruptedException e) {
//			e.printStackTrace();
//		}
		v3.getSnmpV3Req();
	}
}
