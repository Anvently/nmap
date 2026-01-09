# Scan connect (sT)

Ne nécessite pas les droits admins, utilise le syscall connect()

# Scan SYN (sS)

Envoie un paquet TCP brut contenant un simple SYN et attendant SYN/RST/ACK en retour.
Détermine les états ouvert/fermé/filtré
SYN (avec ou sans ACK) = ouvert
RST = fermé
Pas de réponse après plusieurs tentatives OU ICMP port unreachable = filtré

# Scan UDP (sU)

Peut être lancé simultanément à SYN (comment ?)
Envoie un paquet UDM à chaque port
Pour les ports 53 ete 161 (un paquet protocole-spécifique est envoyé)

ICMP port unreachable (code 3) => fermé
ICMP port unreachable (code 0, 1, 2, 9, 10 ou 13) => filtré
Paquet UDP => ouvert
No response after retransmission => open|filtered, version detection (sV) peut aider
!! VERY SLOW !! => dest unreachable message limitation are 1/sec
To speed up : use --host-timeout to skip slow host, scan multiple host in parallel or scan the popular ports only

# Scan ACK (sA)

Détermine si un port est filtré ou non (pas si il est ouvert/fermé).
Envoie un seul paquet avec le ACK flag activé
Si RST => unfiltered
Pas de réponse ou ICMP un reachable (type 3) => filtered

# Scan NULL (sN), FIN (sF) et Xmas (sX)

Permet de déterminer si unport est fermé ou ouvert
Lire RFC 793
Si FERME: un paquet reçu qui ne contient pas de RST doit être répondu avec RST
Si OUVERT: un paquet reçu sans SYN, RST ou ACK bit doit rester sans réponse
Si FILTRE : ICMP unreachable (type 3) ou absence de réponse

Donc dans les deux cas, aucun des 3 bits est set.
Le reste des bits (NULL, FIN, Xmas, ...) peut-être défini arbitrairement:
NULL : aucun  des 3 bits
FIN : juste le FIN
Xmas : active FIN, PSH et URG ("lighting the packet up like a Christmas tree.") 

DONC:
RST => fermé
ICMP error => filtré
Pas de réponse => ouvert | filtré

Avantage : pas statefull (??) : "ils peuvent furtivement traverser certains pare-feux ou routeurs filtrants sans état de connexion (non-statefull)"
Attention : Windows a tendance à renvoyer des RST lorsque les ports sont ouvert.