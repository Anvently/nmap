
# Algorithme

1. Parsing des arguments
	- définition de la liste des hotes
	- parsing de la plage de port à scanner
2. Allocation des hôtes et des arrays de struct port_info
3. Boucle principale :
   1. Estimation du nombre de worker maximal selon la situation :
      - 1 worker/hote
      - max(nombre d'hôte restant, max_thread)
    2. Si nombre idéal de worker =  0 => NMAP DONE 
    3. Tant que le nombre max de worker n'est pas atteint :
        1.  Création d'un scan_worker :
			- Assignation d'un hôte disponible
            - Assignation des handlers
            - Appel de la fonction init 
			- Lancement du thread
			- Création du polling dans la boucle principal du thread
   2. Si un hôte est complètement scanné : on l'affiche

4. worker_switch
   1. Si flag send_tate toggled, polling avec timeout
      1. Si qlq chose a lire, on toggle flag rcv
      2. si timeout, toggle flag timeout
   2. Handlers selon l'étape : init, packet_send, packet_rcv, packet_timeout, release
      - DNS host H:
         - init : 
      - PING host H:
      	- init : raw TCP socket (binded + connected to HOST:80) with IP_RECVERR + ephemeral SOCK_STREAM socket
      	- packet_send : send ICMP echo + TCP SYN
      	- packet_rcv : rcv TCP response or ICMP error/response
      	- packet_timeout : close or resend
      	- release : close sockets
      - TCP port P :
		- init : raw TCP socket (binded + connected to HOST:P) with IP_RECVERR + ephemeral SOCK_STREAM socket
		- packet_send : send syn_ack OU syn_rst
		- packet_rcv : receive TCP answer ou ICMP error
		- packet_timeout : close conn or resend
		- release : close sockets
	 - UDP port P:
		- init : UDP socket with IP_RECVERR, binded to ephemeral port + connected (HOST:P)
		- packet_send : send probe
		- packet_rcv : receive UDP answer ou ICMP error
		- packet_timeout : close or resend
		- release : close sockets
	 - CONN port P:
		- init : TCP SOCK_STREAM socket, binded to ephemeral port.
		- packet_send : connect(), blocking
		- packet_rcv : null
		- packet_timeout : null
		- release : close socket
   3. Si qlq chose à lire : packet_rcv()
   4. Si qlq chose à envoyer : packet_send()
   5. Si timeout : packet_timeout()
   6. Si terminé : release()
   7. Si Complet
      1. fermeture des sockets
      2. arrêt du thread

**Exemple de prototype du worker switch :**

```C
 /* 
	For multithread : called by thread main loop, which have its own polling instance.
	For asynchronous : called by main event loop, with a shared polling instance.
  */
 int	worker_switch(t_worker* data, struct pollfd* readfds, unsigned int nfds);
```

# Constant

- **PING_TIMEOUT** : 3s
- 

enum host_state {
	STATE_ERROR = -2, // Error received
	STATE_DOWN = -1, // Ping failed (host unreachable)

	STATE_PENDING_RESOLVE = 0, // Was inputed by user

	// blocking
	// DNS
	STATE_RESOLVING, // Dns resolution pending
	STATE_RESOLVED, // Dns resolution done
	STATE_RESOLVE_FAILED, // Dns resolution failed

	// Ping
	STATE_PING_PENDING, // Need to send a ping
	STATE_PING_SENT, // Waiting for ping response
	STATE_PING_TIMEOUT, // No response after timeout
	STATE_UP, // Ping sucedeed

	// Scan
	STATE_SCAN_PENDING, // No scan
	STATE_SCAN_RUNNING, // A scan is in progress
	STATE_SCAN_DONE, // All required scan are done
};

enum scan_state {
	SCAN_DISABLE = 0,
	SCAN_PENDING,
	SCAN_RUNNING,
	SCAN_DONE,
} __attribute__ ((__packed__));

enum scan_type {
	SCAN_SYN = 0,
	SCAN_ACK,
	SCAN_NULL,
	SCAN_FIN,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_CONNECT,
	SCAN_NBR
} __attribute__ ((__packed__));



struct port_info {
	uint16_t	port; // 1-65535
	enum port_state	state;
	struct {
		uint8_t	ttl;
		union {
			enum connect_reason	connect;

		} u;
	} reason;
} __attribute__ ((__packed__));

struct scan_result {
	enum scan_type	type;
	enum scan_state	state;

} __attribute__ ((__packed__));


struct host {
	struct sockaddr_in addr;
	char	rsl_hostname[]; // FQDN - resolved host with getnameinfo()
	char*	hostname
	enum host_state	state;
	struct scan_result	 scans[SCAN_NBR];
	union nmap_error	error;
};

struct nmap_error {
	int errno;
	union { // Examples
		struct {
		
		} dns;
		struct {
			struct icmphdr	icmphdr;
			uint8_t	detail[8];
		} ping;
		struct {

		} scan;
	} u;
}
