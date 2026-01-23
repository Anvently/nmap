# Architecture UML - Network Mapper

## Diagramme de classes

```mermaid
classDiagram
    class Options {
        +bool verbose
        +bool help
        +uint size
        +bool numeric
        +bool resolve
        +string interface
        +string pattern
        +uint8_t ttl
        +bool sequential
        +uint16_t mtu
        +UsurpInfo usurp
        +bool reason
        +bool list
        +bool skip_discovery
        +uint16_t src_port
        +bool open
        +bool all
        +uint16_t* ports
        +uint16_t threads
        +uint8_t scan
        +string file
    }
    
    class UsurpInfo {
        +string arg
        +in_addr addr
    }
    
    class Host {
        +sockaddr_in addr
        +string hostname_rsvl
        +string hostname
        +HostState state
        +ScanResult[SCAN_NBR] scans
    }
    
    class ScanResult {
        +ScanType type
        +ScanState state
        +uint16_t remaining
        +PortInfo* ports
        +NmapError* error
    }
    
    class PortInfo {
        +uint16_t port
        +PortState state
        +ReasonInfo reason
        +NmapError* error
    }
    
    class ReasonInfo {
        +uint8_t ttl
        +ResultReason type
    }
    
    class NmapError {
        +int error
        +ErrorUnion u
    }
    
    class WorkerHandle {
        +TaskHandle* tasks
        +uint nbr_tasks
        +execute()
    }
    
    class TaskHandle {
        +ScanType scan_type
        +TaskData data
        +timeval timeout
        +TaskFlags flags
        +NmapError** error
        +int (*init)()
        +int (*packet_send)()
        +int (*packet_rcv)()
        +int (*packet_timeout)()
        +int (*release)()
    }
    
    class TaskFlags {
        +bit initialized
        +bit send_state
        +bit main_rcv
        +bit icmp_rcv
        +bit timeout
        +bit done
        +bit error
    }
    
    class TaskData {
        <<union>>
        +DnsData dns
        +PingData ping
        +TcpData tcp
        +ConnectData connect
        +UdpData udp
    }
    
    class DnsData {
        +string** hostname_rslv_ptr
    }
    
    class PingData {
        +int sock_eph
        +int sock_tcp
        +int sock_icmp
        +in_addr daddr
        +sockaddr_in saddr
        +ScanResult* rslt
    }
    
    class TcpData {
        +uint8_t flag
        +int sock_eph
        +int sock_tcp
        +PortInfo* port
    }
    
    class ConnectData {
        +int sock_stream
        +in_addr daddr
        +PortInfo* port
    }
    
    class UdpData {
        +int sock_udp
        +in_addr daddr
        +PortInfo* port
    }
    
    class HostState {
        <<enumeration>>
        STATE_ERROR
        STATE_DOWN
        STATE_PENDING_RESOLVE
        STATE_RESOLVING
        STATE_RESOLVED
        STATE_RESOLVE_FAILED
        STATE_PING_PENDING
        STATE_PING_SENT
        STATE_PING_TIMEOUT
        STATE_UP
        STATE_SCAN_PENDING
        STATE_SCAN_RUNNING
        STATE_SCAN_DONE
    }
    
    class ScanState {
        <<enumeration>>
        SCAN_DISABLE
        SCAN_PENDING
        SCAN_RUNNING
        SCAN_DONE
    }
    
    class ScanType {
        <<enumeration>>
        SCAN_DNS
        SCAN_PING
        SCAN_SYN
        SCAN_ACK
        SCAN_NULL
        SCAN_FIN
        SCAN_XMAS
        SCAN_UDP
        SCAN_CONNECT
    }
    
    class PortState {
        <<enumeration>>
        PORT_UNKNOWN
        PORT_SCANNING
        PORT_OPENED
        PORT_CLOSED
        PORT_FILTERED
        PORT_UNFILTERED
        PORT_OPEN_FILTERED
        PORT_CLOSED_FILTERED
    }
    
    class ResultReason {
        <<enumeration>>
        REASON_UNKNOWN
        REASON_SYN_ACK
        REASON_RST
        REASON_PORT_UNREACH
        REASON_CONN_REFUSED
        REASON_NO_RESPONSE
    }

    %% Relations
    Options *-- UsurpInfo
    
    Host *-- "SCAN_NBR" ScanResult : contains
    Host -- HostState : has state
    
    ScanResult *-- "*" PortInfo : contains
    ScanResult -- ScanState : has state
    ScanResult -- ScanType : has type
    ScanResult o-- NmapError : may have
    
    PortInfo *-- ReasonInfo : contains
    PortInfo -- PortState : has state
    PortInfo o-- NmapError : may have
    
    ReasonInfo -- ResultReason : has type
    
    WorkerHandle *-- "*" TaskHandle : manages (max 16)
    
    TaskHandle *-- TaskData : contains
    TaskHandle *-- TaskFlags : contains
    TaskHandle -- ScanType : has type
    TaskHandle o-- NmapError : may register
    
    TaskData o-- DnsData
    TaskData o-- PingData
    TaskData o-- TcpData
    TaskData o-- ConnectData
    TaskData o-- UdpData
    
    DnsData ..> Host : resolves hostname
    PingData ..> ScanResult : writes to
    TcpData ..> PortInfo : writes to
    ConnectData ..> PortInfo : writes to
    UdpData ..> PortInfo : writes to
```

## Diagramme de séquence - Flux principal

```mermaid
sequenceDiagram
    participant Main as Main Thread
    participant Host as Host
    participant Worker as Worker Thread
    participant Task as Task Handle
    participant Network as Network

    Main->>Main: Parse arguments
    Main->>Host: Allocate hosts & port arrays
    
    loop Main Loop
        Main->>Main: Calculate max workers needed
        
        alt workers needed > 0
            Main->>Worker: Create worker thread
            Main->>Host: Assign host to worker
            Main->>Task: Create task(s) for worker
            Main->>Task: init()
            Worker->>Worker: Start polling loop
            
            loop Worker Loop
                alt send_state toggled
                    Task->>Task: packet_send()
                    Task->>Network: Send packet (ICMP/TCP/UDP)
                    Worker->>Worker: Poll with timeout
                    
                    alt Response received
                        Network->>Task: Response packet
                        Task->>Task: Toggle rcv flag
                        Task->>Task: packet_rcv()
                        Task->>PortInfo: Update state
                    else Timeout
                        Task->>Task: Toggle timeout flag
                        Task->>Task: packet_timeout()
                    end
                end
                
                alt Task done
                    Task->>Task: release()
                    Task->>Task: Close sockets
                    Worker->>Main: Task complete
                end
            end
            
            alt Host completely scanned
                Main->>Main: Display host results
            end
        else
            Main->>Main: NMAP DONE
        end
    end
```
            
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
**end**
        else
            Main->>Main: NMAP DONE
        end
    end
```

## Diagramme d'états - Host State Machine

```mermaid
stateDiagram-v2
    [*] --> PENDING_RESOLVE: User input
    
    PENDING_RESOLVE --> RESOLVING: DNS worker assigned
    RESOLVING --> RESOLVED: DNS success
    RESOLVING --> RESOLVE_FAILED: DNS failure
    
    RESOLVED --> PING_PENDING: Need ping
    RESOLVED --> SCAN_PENDING: Skip ping
    
    PING_PENDING --> PING_SENT: Ping sent
    PING_SENT --> UP: Response received
    PING_SENT --> PING_TIMEOUT: Timeout
    PING_TIMEOUT --> DOWN: Max retries
    PING_TIMEOUT --> PING_PENDING: Retry
    
    UP --> SCAN_PENDING: Start scans
    SCAN_PENDING --> SCAN_RUNNING: Worker assigned
    SCAN_RUNNING --> SCAN_DONE: All scans complete
    
    SCAN_DONE --> [*]
    DOWN --> [*]
    ERROR --> [*]: Unrecoverable error
```

## Diagramme d'états - Port State Machine

```mermaid
stateDiagram-v2
    [*] --> PORT_UNKNOWN: Initial state
    
    PORT_UNKNOWN --> PORT_SCANNING: Worker starts scan
    
    PORT_SCANNING --> PORT_OPENED: SYN-ACK received (SYN), UDP response (UDP)
    PORT_SCANNING --> PORT_CLOSED: RST (SYN/NULL/FIN/XMAS), ICMP port unreachable (UDP)
    PORT_SCANNING --> PORT_FILTERED: ICMP unreachable or no response (ACK/SYN) 
    PORT_SCANNING --> PORT_UNFILTERED: RST in ACK scan
    PORT_SCANNING --> PORT_OPEN_FILTERED: No response (UDP/NULL/FIN/XMAS)
    PORT_SCANNING --> PORT_CLOSED_FILTERED: Special case (IDLE SCAN)
    
    PORT_OPENED --> [*]
    PORT_CLOSED --> [*]
    PORT_FILTERED --> [*]
    PORT_UNFILTERED --> [*]
    PORT_OPEN_FILTERED --> [*]
    PORT_CLOSED_FILTERED --> [*]
```

## Diagramme de composants - Architecture Threading

```mermaid
graph TB
    subgraph "Main Thread"
        Parser[Argument Parser]
        Allocator[Host/Port Allocator]
        WorkerManager[Worker Manager]
        Display[Results Display]
    end
    
    subgraph "Worker Pool (max 250)"
        W1[Worker 1<br/>1/16 tasks]
        W2[Worker 2<br/>1/16 tasks]
        W3[Worker 3<br/>1/16 tasks]
        W4[Worker 4<br/>1/16 tasks]
        W5[Worker 5<br/>1/16 tasks]
        W6[Worker 6<br/>1/16 tasks]
        W7[Worker 7<br/>1/16 tasks]
        W8[Worker N<br/>3/16 tasks]
    end
    
    subgraph "Task Types"
        subgraph "Host 1 (google.com)"
            DNS[DNS Resolution<br/>google.com]
        end
        subgraph "Host 2 (10.14.8.7)"
            PING[ICMP/TCP Ping<br>10.14.8.7:80]
        end
        subgraph "Host 3 (47.11.2.7)"
            ACK[ACK Scan<br/>47.11.2.7:79]
        end
        subgraph "Host 4 (167.8.2.9)"
            NULL[NULL Scan<br/>167.8.2.9:889]
        end
        subgraph "Host 5 (8.29.3.9)"
            FIN[FIN Scan<br/>8.29.3.9:47]
        end
        subgraph "Host 6 (10.74.89.2)"
            XMAS[XMAS Scan<br/>10.74.89.2:443]
        end
        subgraph "Host 7 (49.6.5.2)"
            CONNECT[Connect Scan<br/>49.6.5.2:443]
        end
        subgraph H8["Host 8 (172.217.20.46)"]
            SYN[SYN Scan<br/>172.217.20.46:80]
            subgraph "UDP Scan"
                UDP1[UDP Scan<br/>172.217.20.46:21]
                UDP2[UDP Scan<br/>172.217.20.46:22]
            end
        end
    end
    
    subgraph "Network Layer"
        PING_ICMP[ICMP Socket]
        PING_TCP[RAW TCP Socket]
        ACK_TCP[Raw TCP Socket]
        NULL_TCP[Raw TCP Socket]
        FIN_TCP[Raw TCP Socket]
        XMAS_TCP[Raw TCP Socket]
        CONNECT_STREAM[Stream Socket]
        SYN_TCP[Raw TCP Socket]
        UDP1_SOCK[UDP Socket]
        UDP2_SOCK[UDP Socket]
    end
    
    Parser --> Allocator
    Allocator --> WorkerManager
    WorkerManager --> W1
    WorkerManager --> W2
    WorkerManager --> W8
    
    W1 --> DNS
    W2 --> PING
    W3 --> ACK
    W4 --> NULL
    W5 --> FIN
    W6 --> XMAS
    W7 --> CONNECT
    W8 --> UDP1
    W8 --> UDP2
    W8 --> SYN
    
    DNS --> Stream[getaddrinfo]
    PING --> PING_ICMP
    PING --> PING_TCP
    ACK --> ACK_TCP
    NULL --> NULL_TCP
    FIN --> FIN_TCP
    XMAS --> XMAS_TCP
    CONNECT --> CONNECT_STREAM
    SYN --> SYN_TCP
    UDP1 --> UDP1_SOCK
    UDP2 --> UDP2_SOCK
    
    WorkerManager --> Display
```

## Notes d'architecture

### Concepts clés

1. **Worker vs Task**
   - 1 Worker = 1 Thread = 1 boucle de polling
   - 1 Worker peut gérer jusqu'à 16 tâches simultanément
   - Seul le scan UDP peut scanner plusieurs ports d'un même hôte

2. **Gestion des états**
   - Les hôtes passent par plusieurs états (DNS → Ping → Scan)
   - Les ports ont leur propre machine d'états
   - Les tâches utilisent des flags pour la synchronisation

3. **Handlers de tâches**
   - `init()`: Initialisation (création sockets)
   - `packet_send()`: Envoi des paquets
   - `packet_rcv()`: Réception et traitement
   - `packet_timeout()`: Gestion timeout
   - `release()`: Nettoyage (fermeture sockets)

4. **Types de sockets**
   - Raw TCP: Pour SYN, ACK, NULL, FIN, XMAS scans
   - ICMP: Pour ping
   - UDP: Pour scan UDP
   - Stream: Pour scan CONNECT et lock de ports éphémères

5. **Contraintes**
   - Maximum 250 workers (threads)
   - Maximum 16 tâches par worker
   - Timeout configurable (PING_TIMEOUT = 5s)
