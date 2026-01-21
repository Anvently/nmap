- [HELP](#help)
- [EXEMPLES:](#exemples)
	- [open](#open)
- [Scan methods](#scan-methods)
	- [-sS (TCP SYN scan)](#-ss-tcp-syn-scan)
	- [-sT (TCP connect scan)](#-st-tcp-connect-scan)
	- [-sU (UDP scans)](#-su-udp-scans)
	- [-sN; -sF; -sX (TCP NULL, FIN, and Xmas scans)](#-sn--sf--sx-tcp-null-fin-and-xmas-scans)
	- [-sA (TCP ACK scan)](#-sa-tcp-ack-scan)
- [Options](#options)
	- [-f (fragment packets); --mtu (using the specified MTU)](#-f-fragment-packets---mtu-using-the-specified-mtu)
	- [-S IP\_Address (Spoof source address)](#-s-ip_address-spoof-source-address)
- [-n(Pas de résolution DNS)](#-npas-de-résolution-dns)
- [-R(Résolution DNS pour toutes les cibles)](#-rrésolution-dns-pour-toutes-les-cibles)


```
As a novice performing automotive repair, I can struggle for hours trying to fit my rudimentary tools (hammer, duct tape, wrench, etc.) to the task at hand. When I
fail miserably and tow my jalopy to a real mechanic, he invariably fishes around in a huge tool chest until pulling out the perfect gizmo which makes the job seem
effortless. The art of port scanning is similar. Experts understand the dozens of scan techniques and choose the appropriate one (or combination) for a given task.
Inexperienced users and script kiddies, on the other hand, try to solve every problem with the default SYN scan. Since Nmap is free, the only barrier to port
scanning mastery is knowledge. That certainly beats the automotive world, where it may take great skill to determine that you need a strut spring compressor, then
you still have to pay thousands of dollars for it.

```
# HELP
```
Nmap 4.50 (insecure.org)
Utilisation: nmap [Type(s) de scan] [Options] {spécifications des cibles}

SPÉCIFICATIONS DES CIBLES:
Les cibles peuvent être spécifiées par des noms d'hôtes, des adresses IP, des adresses de réseaux, etc.
Exemple: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0-255.0-255.1-254
-iL <inputfilename>: Lit la liste des hôtes/réseaux cibles à partir du fichier
-iR <num hosts>: Choisit les cibles au hasard
--exclude <host1[,host2][,host3],...>: Exclut des hôtes/réseaux du scan 
--excludefile <exclude_file>: Exclut des hôtes/réseaux des cibles à partir du fichier

DÉCOUVERTE DES HÔTES:
-sL: List Scan - Liste simplement les cibles à scanner
-sn: Ping Scan - Ne fait que déterminer si les hôtes sont en ligne
-Pn: Considérer tous les hôtes comme étant connectés -- saute l'étape de découverte des hôtes
-PS/PA/PU [portlist]: Découverte TCP SYN/ACK ou UDP des ports en paramètre
-PE/PP/PM: Découverte de type requête ICMP echo, timestamp ou netmask 
-PO [num de protocole]: Ping IP (par type)
-n/-R: Ne jamais résoudre les noms DNS/Toujours résoudre [résout les cibles actives par défaut]
--dns-servers <serv1[,serv2],...>: Spécifier des serveurs DNS particuliers

TECHNIQUES DE SCAN:
-sS/sT/sA/sW/sM: Scans TCP SYN/Connect()/ACK/Window/Maimon 
-sN/sF/sX: Scans TCP Null, FIN et Xmas
-sU: Scan UDP
--scanflags <flags>: Personnalise les flags des scans TCP
-sI <zombie host[:probeport]>: Idlescan (scan passif)
-sO: Scan des protocoles supportés par la couche IP
-b <ftp relay host>: Scan par rebond FTP
--traceroute: Détermine une route vers chaque hôte
--reason: Donne la raison pour laquelle tel port apparait à tel état

SPÉCIFICATIONS DES PORTS ET ORDRE DE SCAN:
-p <plage de ports>: Ne scanne que les ports spécifiés
Exemple: -p22; -p1-65535; -pU:53,111,137,T:21-25,80,139,8080
-F: Fast - Ne scanne que les ports listés dans le fichier nmap-services
-r: Scan séquentiel des ports, ne mélange pas leur ordre
--top-ports <nombre>: Scan <nombre> de ports parmis les plus courants
--port-ratio <ratio>: Scan <ratio> pourcent des ports les plus courants
 
DÉTECTION DE SERVICE/VERSION:
-sV: Teste les ports ouverts pour déterminer le service en écoute et sa version
--version-light: Limite les tests aux plus probables pour une identification plus rapide
--version-intensity <niveau>: De 0 (léger) à 9 (tout essayer)
--version-all: Essaie un à un tous les tests possibles pour la détection des versions
--version-trace: Affiche des informations détaillées du scan de versions (pour débogage)

SCRIPT SCAN:
-sC: équivalent de --script=safe,intrusive
--script=<lua scripts>: <lua scripts> est une liste de répertoires ou de scripts séparés par des virgules
--script-args=<n1=v1,[n2=v2,...]>: passer des arguments aux scripts
--script-trace: Montre toutes les données envoyées ou recues
--script-updatedb: Met à jour la base de données des scripts. Seulement fait si -sC ou --script a été aussi donné.

DÉTECTION DE SYSTÈME D'EXPLOITATION:
-O: Active la détection d'OS
--osscan-limit: Limite la détection aux cibles prometteuses
--osscan-guess: Devine l'OS de façon plus agressive

TEMPORISATION ET PERFORMANCE:
Les options qui prennent un argument de temps sont en milisecondes a moins que vous ne spécifiiez 's'
(secondes), 'm' (minutes), ou 'h' (heures) à la valeur (e.g. 30m).

-T[0-5]: Choisit une politique de temporisation (plus élevée, plus rapide)
--min-hostgroup/max-hostgroup <nombre>: Tailles des groupes d'hôtes à scanner en parallèle
--min-parallelism/max-parallelism <nombre>: Parallélisation des paquets de tests (probes)
--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <msec>: Spécifie le temps d'aller-retour des paquets de tests
--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <msec>: Spécifie le temps d'aller-retour des paquets de tests
--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Précise
le round trip time des paquets de tests.
--max-retries <tries>: Nombre de retransmissions des paquets de tests des scans de ports.
--host-timeout <msec>: Délai d'expiration du scan d'un hôte --scan-delay/--max-scan-delay <msec>: Ajuste le délai de retransmission entre deux paquets de tests
--scan-delay/--max-scan-delay <time>: Ajuste le delais entre les paquets de tests.

ÉVASION PARE-FEU/IDS ET USURPATION D'IDENTITÉ
-f; --mtu <val>: Fragmente les paquets (en spécifiant éventuellement la MTU)
-D <decoy1,decoy2[,ME],...>: Obscurci le scan avec des leurres
-S <IP_Address>: Usurpe l'adresse source
-e <iface>: Utilise l'interface réseau spécifiée
-g/--source-port <portnum>: Utilise le numéro de port comme source
--data-length <num>: Ajoute des données au hasard aux paquets émis
--ip-options <options>: Envoi des paquets avec les options IP spécifiées. 
--ttl <val>: Spécifie le champ time-to-live IP
--spoof-mac <adresse MAC, préfixe ou nom du fabriquant>: Usurpe une adresse MAC
--badsum: Envoi des paquets TCP/UDP avec une somme de controle erronnée.

SORTIE:
-oN/-oX/-oS/-oG <file>: Sortie dans le fichier en paramètre des résultats du scan au format normal, XML, s|<rIpt kIddi3 et Grepable, respectivement
-oA <basename>: Sortie dans les trois formats majeurs en même temps
-v: Rend Nmap plus verbeux (-vv pour plus d'effet)
-d[level]: Sélectionne ou augmente le niveau de débogage (significatif jusqu'à 9)
--packet-trace: Affiche tous les paquets émis et reçus
--iflist: Affiche les interfaces et les routes de l'hôte (pour débogage)
--log-errors: Journalise les erreurs/alertes dans un fichier au format normal
--append-output: Ajoute la sortie au fichier plutôt que de l'écraser 
--resume <filename>: Reprend un scan interrompu
--stylesheet <path/URL>: Feuille de styles XSL pour transformer la sortie XML en HTML
--webxml: Feuille de styles de références de Insecure.Org pour un XML plus portable
--no-stylesheet: Nmap n'associe pas la feuille de styles XSL à la sortie XML

DIVERS:
-6: Active le scan IPv6
-A: Active la détection du système d'exploitation et des versions
--datadir <dirname>: Spécifie un dossier pour les fichiers de données de Nmap
--send-eth/--send-ip: Envoie des paquets en utilisant des trames Ethernet ou des paquets IP bruts
--privileged: Suppose que l'utilisateur est entièrement privilégié 
-V: Affiche le numéro de version
--unprivileged: Suppose que l'utilisateur n'a pas les privilèges d'usage des raw socket
-h: Affiche ce résumé de l'aide


```
# EXEMPLES:
nmap -v -A scanme.nmap.org
nmap -v -sP 192.168.0.0/16 10.0.0.0/8

# The six port states recognized by Nmap

## open
	An application is actively accepting TCP connections, UDP datagrams or SCTP associations on this port. Finding these is often the primary goal of port scanning.
	Security-minded people know that each open port is an avenue for attack. Attackers and pen-testers want to exploit the open ports, while administrators try to
	close or protect them with firewalls without thwarting legitimate users. Open ports are also interesting for non-security scans because they show services
	available for use on the network.

## closed
	A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it. They can be helpful in showing that a
	host is up on an IP address (host discovery, or ping scanning), and as part of OS detection. Because closed ports are reachable, it may be worth scanning later
	in case some open up. Administrators may want to consider blocking such ports with a firewall. Then they would appear in the filtered state, discussed next.

## filtered
	Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port. The filtering could be from a dedicated
	firewall device, router rules, or host-based firewall software. These ports frustrate attackers because they provide so little information. Sometimes they
	respond with ICMP error messages such as type 3 code 13 (destination unreachable: communication administratively prohibited), but filters that simply drop probes
	without responding are far more common. This forces Nmap to retry several times just in case the probe was dropped due to network congestion rather than
	filtering. This slows down the scan dramatically.

## unfiltered
	The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed. Only the ACK scan, which is used to map firewall rulesets, classifies ports into this state. Scanning unfiltered ports with other scan types such as Window scan, SYN scan, or FIN scan, may help resolve whether the port is open.

## open|filtered
	Nmap places ports in this state when it is unable to determine whether a port is open or filtered. This occurs for scan types in which open ports give no
	response. The lack of response could also mean that a packet filter dropped the probe or any response it elicited. So Nmap does not know for sure whether the
	port is open or being filtered. The UDP, IP protocol, FIN, NULL, and Xmas scans classify ports this way.

## closed|filtered
	This state is used when Nmap is unable to determine whether a port is closed or filtered. It is only used for the IP ID idle scan.

# Scan methods

## -sS (TCP SYN scan)
	SYN scan is the default and most popular scan option for good reasons. It can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls. It is also relatively unobtrusive and stealthy since it never completes TCP connections. SYN scan works against any compliant TCP stack rather than depending on idiosyncrasies of specific platforms as Nmap's FIN/NULL/Xmas, Maimon and idle scans do. It also allows clear, reliable differentiation between the open, closed, and filtered states.

	This technique is often referred to as half-open scanning, because you don't open a full TCP connection. You send a SYN packet, as if you are going to open a
	real connection and then wait for a response. A SYN/ACK indicates the port is listening (open), while a RST (reset) is indicative of a non-listener. If no
	response is received after several retransmissions, the port is marked as filtered. The port is also marked filtered if an ICMP unreachable error (type 3, code
	0, 1, 2, 3, 9, 10, or 13) is received. The port is also considered open if a SYN packet (without the ACK flag) is received in response. This can be due to an
	extremely rare TCP feature known as a simultaneous open or split handshake connection (see https://nmap.org/misc/split-handshake.pdf).

## -sT (TCP connect scan)
	TCP connect scan is the default TCP scan type when SYN scan is not an option. This is the case when a user does not have raw packet privileges. Instead of
	writing raw packets as most other scan types do, Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing
	the connect system call. This is the same high-level system call that web browsers, P2P clients, and most other network-enabled applications use to establish a
	connection. It is part of a programming interface known as the Berkeley Sockets API. Rather than read raw packet responses off the wire, Nmap uses this API to
	obtain status information on each connection attempt.

	When SYN scan is available, it is usually a better choice. Nmap has less control over the high level connect call than with raw packets, making it less
	efficient. The system call completes connections to open target ports rather than performing the half-open reset that SYN scan does. Not only does this take
	longer and require more packets to obtain the same information, but target machines are more likely to log the connection. A decent IDS will catch either, but
	most machines have no such alarm system. Many services on your average Unix system will add a note to syslog, and sometimes a cryptic error message, when Nmap
	connects and then closes the connection without sending data. Truly pathetic services crash when this happens, though that is uncommon. An administrator who sees
	a bunch of connection attempts in her logs from a single system should know that she has been connect scanned.

## -sU (UDP scans)
	While most popular services on the Internet run over the TCP protocol, UDP[5] services are widely deployed. DNS, SNMP, and DHCP (registered ports 53, 161/162,
	and 67/68) are three of the most common. Because UDP scanning is generally slower and more difficult than TCP, some security auditors ignore these ports. This is
	a mistake, as exploitable UDP services are quite common and attackers certainly don't ignore the whole protocol. Fortunately, Nmap can help inventory UDP ports.

	UDP scan is activated with the -sU option. It can be combined with a TCP scan type such as SYN scan (-sS) to check both protocols during the same run.

	UDP scan works by sending a UDP packet to every targeted port. For some common ports such as 53 and 161, a protocol-specific payload is sent to increase response
	rate, but for most ports the packet is empty unless the --data, --data-string, or --data-length options are specified. If an ICMP port unreachable error (type 3,
	code 3) is returned, the port is closed. Other ICMP unreachable errors (type 3, codes 0, 1, 2, 9, 10, or 13) mark the port as filtered. Occasionally, a service
	will respond with a UDP packet, proving that it is open. If no response is received after retransmissions, the port is classified as open|filtered. This means
	that the port could be open, or perhaps packet filters are blocking the communication. Version detection (-sV) can be used to help differentiate the truly open
	ports from the filtered ones.

	A big challenge with UDP scanning is doing it quickly. Open and filtered ports rarely send any response, leaving Nmap to time out and then conduct
	retransmissions just in case the probe or response were lost. Closed ports are often an even bigger problem. They usually send back an ICMP port unreachable
	error. But unlike the RST packets sent by closed TCP ports in response to a SYN or connect scan, many hosts rate limit ICMP port unreachable messages by default.
	Linux and Solaris are particularly strict about this. For example, the Linux 2.4.20 kernel limits destination unreachable messages to one per second (in
	net/ipv4/icmp.c).

	Nmap detects rate limiting and slows down accordingly to avoid flooding the network with useless packets that the target machine will drop. Unfortunately, a
	Linux-style limit of one packet per second makes a 65,536-port scan take more than 18 hours. Ideas for speeding your UDP scans up include scanning more hosts in
	parallel, doing a quick scan of just the popular ports first, scanning from behind the firewall, and using --host-timeout to skip slow hosts.

## -sN; -sF; -sX (TCP NULL, FIN, and Xmas scans)
	These three scan types (even more are possible with the --scanflags option described in the next section) exploit a subtle loophole in the TCP RFC[7] to
	differentiate between open and closed ports. Page 65 of RFC 793 says that “if the [destination] port state is CLOSED .... an incoming segment not containing a
	RST causes a RST to be sent in response.”  Then the next page discusses packets sent to open ports without the SYN, RST, or ACK bits set, stating that: “you are
	unlikely to get here, but if you do, drop the segment, and return.”

	When scanning systems compliant with this RFC text, any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no
	response at all if the port is open. As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK. Nmap
	exploits this with three scan types:

	Null scan (-sN)
		Does not set any bits (TCP flag header is 0)

	FIN scan (-sF)
		Sets just the TCP FIN bit.

	Xmas scan (-sX)
		Sets the FIN, PSH, and URG flags, lighting the packet up like a Christmas tree.

	These three scan types are exactly the same in behavior except for the TCP flags set in probe packets. If a RST packet is received, the port is considered
	closed, while no response means it is open|filtered. The port is marked filtered if an ICMP unreachable error (type 3, code 0, 1, 2, 3, 9, 10, or 13) is
	received.

	The key advantage to these scan types is that they can sneak through certain non-stateful firewalls and packet filtering routers. Another advantage is that these scan types are a little more stealthy than even a SYN scan. Don't count on this though—most modern IDS products can be configured to detect them. The big
	downside is that not all systems follow RFC 793 to the letter. A number of systems send RST responses to the probes regardless of whether the port is open or
	not. This causes all of the ports to be labeled closed. Major operating systems that do this are Microsoft Windows, many Cisco devices, BSDI, and IBM OS/400.
	This scan does work against most Unix-based systems though. Another downside of these scans is that they can't distinguish open ports from certain filtered ones,
	leaving you with the response open|filtered.

## -sA (TCP ACK scan)
	This scan is different than the others discussed so far in that it never determines open (or even open|filtered) ports. It is used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.

	The ACK scan probe packet has only the ACK flag set (unless you use --scanflags). When scanning unfiltered systems, open and closed ports will both return a RST packet. Nmap then labels them as unfiltered, meaning that they are reachable by the ACK packet, but whether they are open or closed is undetermined. Ports that don't respond, or send certain ICMP error messages back (type 3, code 0, 1, 2, 3, 9, 10, or 13), are labeled filtered.


# Options

## -f (fragment packets); --mtu (using the specified MTU)

	The -f option causes the requested scan (including host discovery scans) to use tiny fragmented IP packets. The idea is to split up the TCP header over
	several packets to make it harder for packet filters, intrusion detection systems, and other annoyances to detect what you are doing. Be careful with this!
	Some programs have trouble handling these tiny packets. The old-school sniffer named Sniffit segmentation faulted immediately upon receiving the first
	fragment. Specify this option once, and Nmap splits the packets into eight bytes or less after the IP header. So a 20-byte TCP header would be split into
	three packets. Two with eight bytes of the TCP header, and one with the final four. Of course each fragment also has an IP header. Specify -f again to use 16
	bytes per fragment (reducing the number of fragments).  Or you can specify your own offset size with the --mtu option. Don't also specify -f if you use
	--mtu. The offset must be a multiple of eight. While fragmented packets won't get by packet filters and firewalls that queue all IP fragments, such as the
	CONFIG_IP_ALWAYS_DEFRAG option in the Linux kernel, some networks can't afford the performance hit this causes and thus leave it disabled. Others can't
	enable this because fragments may take different routes into their networks. Some source systems defragment outgoing packets in the kernel. Linux with the
	iptables connection tracking module is one such example. Do a scan while a sniffer such as Wireshark is running to ensure that sent packets are fragmented.
	If your host OS is causing problems, try the --send-eth option to bypass the IP layer and send raw ethernet frames.

	Fragmentation is only supported for Nmap's raw packet features, which includes TCP and UDP port scans (except connect scan and FTP bounce scan) and OS
	detection. Features such as version detection and the Nmap Scripting Engine generally don't support fragmentation because they rely on your host's TCP stack
	to communicate with target services.

## -S IP_Address (Spoof source address)
	In some circumstances, Nmap may not be able to determine your source address (Nmap will tell you if this is the case). In this situation, use -S with the IP
	address of the interface you wish to send packets through.

	Another possible use of this flag is to spoof the scan to make the targets think that someone else is scanning them. Imagine a company being repeatedly port
	scanned by a competitor! The -e option and -Pn are generally required for this sort of usage. Note that you usually won't receive reply packets back (they
	will be addressed to the IP you are spoofing), so Nmap won't produce useful reports.

# -n(Pas de résolution DNS)

	Indique à Nmap de ne jamais faire la résolution DNS inverse des hôtes actifs qu'il a trouvé. Comme la résolution DNS est souvent lente, ceci accélère les choses. 

# -R(Résolution DNS pour toutes les cibles)

	Indique à Nmap de toujoursfaire la résolution DNS inverse des adresses IP cibles. Normalement, ceci n'est effectué que si une machine est considérée comme active. 

