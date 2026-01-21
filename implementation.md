
# Algorithme

1. Parsing des arguments
	- définition de la liste des hotes
	- parsing de la plage de port à scanner
2. Allocation des hôtes et des arrays de struct port_info
3. Boucle principale :
   1. Estimation du nombre de worker maximal selon la situation :
      - 1 resolver_worker/hote qui n'est pas en état de scan
      - max(nombre de ports restants * nbr_scan, multithreading ? max_thread : MAX_WORKER)
    2. Si nombre idéal de worker =  0 => NMAP DONE 
    3. Tant que le nombre max de worker n'est pas atteint :
       1.  Si un hôte n'est pas scanné :
           1.  Assignation d'un hôte
           2.  Création d'un resolver_worker
           3.  Si multithread : lancement du thread
           4.  Si async : ajout du worker à la pool de worker async
       2.  Si un hôte est prêt à être scanné :
           1.  Assignation d'une combinaison scan/port libre
           2.  Assignation des handlers de scan
           3.  Création d'un scan_worker
           4.  Si multithread : lancement du thread
           5.  Si async : ajout du worker à la pool de worker async
   2. Si un hôte est complètement scanné : on l'affiche
   3. Polling (statique) du pool de worker async
      1. pour chaque worker, si un des fds est pollé, on execute le switch correspondant
4. resolver_switch (executé en boucle par les threads après avoir pollé):
   1. Résolution dns des hôtes // bloquant
   2. Facultatif : filtrage avec ping ICMP et/ou TCP pour vérifier si l'hôte est en ligne
      1. Si socket non ouvert : ouverture des sockets 
      2. Polling des sockets du worker
   
5. worker_switch (executé en boucle par les threads après avoir pollé)
   1. Si socket non ouvert, ouverture des sockets
   2. Polling des sockets
   3. Si qlq chose à lire :
      1. Appel de handle_read_scan
   4. switch en fonction de l'état du scan
   5. Si Complet
      1. fermeture des sockets
      2. arrêt du thread
      3. libération du worker


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
