package Kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private KDC myKDC;

	private Server myFileserver;

	private String currentUser;

	private Ticket tgsTicket = null;

	private long tgsSessionKey; // K(C,TGS)

	private Ticket serverTicket = null;

	private long serverSessionKey; // K(C,S)

	// Konstruktor
	public Client(KDC kdc, Server server) {
		myKDC = kdc;
		myFileserver = server;
	}

	public boolean login(String userName, char[] password) {
		String tgsServerName = "myTGS";
		currentUser = userName;
		//Anmeldung beim KDC, TGS Ticket holen
		TicketResponse ticketResponse = myKDC.requestTGSTicket(userName, tgsServerName, generateNonce());
		//TGS Response Entschlüsseln und auswerten
		if (ticketResponse != null) {//TGS beim KDC Server bekannt
			long pw = generateSimpleKeyForPassword(password);
			if (ticketResponse.decrypt(pw)) {
				//TGS Session Key und Ticket speichern
				tgsSessionKey = ticketResponse.getSessionKey();
				tgsTicket = ticketResponse.getResponseTicket();
				tgsTicket.print();
			}
			//PAssword aus Hauptspeicher löschen
			Arrays.fill(password, '0');
		}
		
		return (tgsTicket != null);
	}

	public boolean showFile(String serverName, String filePath) {
		boolean status = false;
		//Login Prüfen TGS Ticket vorhanden?
		if (tgsTicket != null) {//Ohne TGS Ticket geht nichts	
			//Serverticket vorhanden?
			if (serverTicket == null) {//Kein Serverticket da, neues Anfordern
				long currentTime = (new Date()).getTime();
				Auth tgsAuth = new Auth(currentUser, currentTime);
				tgsAuth.encrypt(tgsSessionKey);
				TicketResponse ticketResponse = myKDC.requestServerTicket(tgsTicket, tgsAuth, serverName, generateNonce());
				ticketResponse.print();
				if(ticketResponse.decrypt(tgsSessionKey)) {
					serverTicket = ticketResponse.getResponseTicket();
					serverSessionKey = ticketResponse.getSessionKey();
				}
			}
			//ServerTicket nun vorhanden? ANsonsten Ticket Response nicht entschlüsselbar etc...
			if(serverTicket != null){
				Auth serverAuth = new Auth(currentUser, (new Date()).getTime());
				serverAuth.encrypt(serverSessionKey);
				//Service anfordern
				status = myFileserver.requestService(serverTicket, serverAuth, "showFile", filePath);
				
			}
			
		
		}
		return status;
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlüssel für ein Passwort zurück, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}
