# ft_nmap — Architecture & Implementation

## Overview

`ft_nmap` is built around a **main thread / worker pool** model. The main thread drives a host state machine and dispatches work to short-lived threads; each thread executes one or more *tasks* (one task = one scan type on one host) using non-blocking I/O via `poll()`.

---

## Core Concepts

### Workers and Tasks

| Entity | Description |
|--------|-------------|
| **Scan** | May refer any available scan but also include initial ping phase (PING scan) et DNS resolution (DNS scan). |
| **Worker** | One POSIX thread, owns a `pollfd` loop. Up to 250 concurrent workers. |
| **Task** | One scan operation (e.g. SYN scan on host X). A worker carries up to 16 tasks simultaneously (adjustable via `--sim-ports` option). |
| **Blocking tasks** | DNS (`getaddrinfo`) and Connect (`connect()`) block the thread — they get a dedicated worker. |
| **Non-blocking tasks** | All other scan types multiplex on a single `poll()` call inside a worker. |

A task is defined by five function pointers set by the main thread before the worker starts:

```c
int (*init)         (struct task_handle *);   // open sockets
int (*packet_send)  (struct task_handle *);   // craft & send probe
int (*packet_rcv)   (struct task_handle *, struct pollfd); // handle reply
int (*packet_timeout)(struct task_handle *);  // handle timeout / retry
int (*release)      (struct task_handle *);   // close sockets
```

### Dynamic RTT Timeout

During the ping phase, the measured round-trip time becomes the baseline for all subsequent per-probe timeouts:

```
probe_timeout = host_rtt × rtt_factor   (default factor: 10×)
probe_timeout = min(probe_timeout, rtt_max)  (default cap: 3 000 ms)
```

If ping is skipped (`--skip-ping`), a conservative default of 500 ms is used.

---

## State Machines

### Host State Machine

```mermaid
stateDiagram-v2
    [*] --> PENDING_RESOLVE : user input

    PENDING_RESOLVE --> RESOLVING      : DNS worker assigned
    PENDING_RESOLVE --> DOUBLOON       : duplicate hostname

    RESOLVING --> RESOLVED             : success
    RESOLVING --> RESOLVE_FAILED       : failure

    RESOLVED --> PING_PENDING          : ping enabled
    RESOLVED --> UP                    : --skip-ping
    RESOLVED --> DOUBLOON              : duplicate IP after resolution

    PING_PENDING --> PING_SENT         : ping worker assigned
    PING_SENT    --> UP                : response received
    PING_SENT    --> DOWN              : host unreachable
    PING_SENT    --> PING_TIMEOUT      : no response

    UP --> SCAN_PENDING                : port scans enabled
    UP --> SCAN_DONE                   : no port scans requested

    SCAN_PENDING --> SCAN_RUNNING      : worker assigned
    SCAN_RUNNING --> SCAN_PENDING      : partial — some scans still pending
    SCAN_RUNNING --> SCAN_DONE         : all scans complete

    SCAN_DONE        --> [*]
    DOWN             --> [*]
    PING_TIMEOUT     --> [*]
    RESOLVE_FAILED   --> [*]
    DOUBLOON         --> [*]
```

Duplicate detection happens **after** DNS resolution so that `google.com` and `www.google.com` resolving to the same IP are correctly deduplicated.

### Port State Machine

```mermaid
stateDiagram-v2
    [*] --> UNKNOWN : allocated

    UNKNOWN --> SCANNING : worker picks up port

    SCANNING --> OPEN           : SYN-ACK (SYN) · UDP reply · connect() success
    SCANNING --> CLOSED         : RST (SYN/NULL/FIN/Xmas) · ICMP port-unreach (UDP) · ECONNREFUSED
    SCANNING --> FILTERED       : ICMP unreachable (SYN/ACK) · no response (SYN)
    SCANNING --> UNFILTERED     : RST (ACK scan)
    SCANNING --> OPEN_FILTERED  : no response (UDP/NULL/FIN/Xmas)
    SCANNING --> ERROR  : error occured (sys error, unexpected packet, ...)

    OPEN           --> [*]
    CLOSED         --> [*]
    FILTERED       --> [*]
    UNFILTERED     --> [*]
    OPEN_FILTERED  --> [*]
    ERROR  --> [*]
```

### Worker State Machine

```mermaid
stateDiagram-v2
    [*] --> AVAILABLE : pool initialised

    AVAILABLE --> RUNNING : pthread_create() success
    AVAILABLE --> AVAILABLE : pthread_create() fails → tasks cancelled

    RUNNING --> DONE : all tasks finished or errored

    DONE --> AVAILABLE : pthread_join() + cleanup by main thread
```

---

## Main Loop

```mermaid
sequenceDiagram
    participant M  as Main Thread
    participant WP as Worker Pool
    participant W  as Worker Thread
    participant N  as Network

    M->>M: parse args, allocate hosts & port arrays

    loop every 1 ms
        alt user_input
            M->>M: update global options
        end
        M->>WP: check for WORKER_DONE
        alt worker finished
            M->>W: pthread_join()
            M->>M: handle results (update host states, print if done)
            M->>WP: mark WORKER_AVAILABLE
        end

        alt all hosts done
            M->>M: break
        end

        alt free worker slot available
            M->>M: find_available_host()
            M->>M: assign_task() × N  — configure handlers & confirm state
            M->>W: pthread_create()
            W-->>N: init() → packet_send()
            loop poll()
                alt reply received
                    N-->>W: packet
                    W->>W: packet_rcv() → update port state
                else timeout
                    W->>W: packet_timeout() → retry or mark filtered
                end
            end
            W->>W: release() → close sockets
            W->>WP: set WORKER_DONE
        end
    end

    M->>M: print final results, free memory
```

---

## Task Lifecycle (inside a worker)

```mermaid
flowchart TD
    A([task assigned]) --> B{initialized?}
    B -- no --> C[init<br />create sockets]
    C --> D{init ok?}
    D -- no --> ERR([cancelled or error])
    D -- yes --> E[set initialized]
    B -- yes --> E
    E --> F{send_state?}
    F -- not set --> G[packet_send<br />craft & transmit]
    G --> H[set send_state<br />configure timeout]
    H --> POLL
    F -- set --> POLL
    POLL([poll / wait]) --> R{event?}
    R -- data in --> I[set main_rcv / icmp_rcv<br />packet_rcv]
    R -- timeout --> J[set timeout<br />packet_timeout]
    I --> K{done?}
    J --> K
    K -- no, retry --> F
    K -- yes --> L[release<br />close sockets]
    L --> END([task done])
```

---

## Scan Type Reference

### Port state determination

| Scan | SYN-ACK | RST | ICMP unreach | No response |
|------|---------|-----|--------------|-------------|
| SYN | `open` | `closed` | `filtered` | `filtered` |
| ACK | — | `unfiltered` | `filtered` | `filtered` |
| NULL / FIN / Xmas | — | `closed` | `filtered` | `open\|filtered` |
| UDP | — | — | `closed` (port) / `filtered` (other) | `open\|filtered` |
| Connect | success → `open` | — | `filtered` | ECONNREFUSED → `closed` |

### Socket types per scan

| Scan | Main socket | Aux socket | Notes |
|------|------------|------------|-------|
| DNS | — | — | `getaddrinfo()` (blocking) |
| Ping | `RAW TCP` +  `RAW ICMP` | Ephemeral lock | `IP_RECVERR` + Bind + connect per port. Sends ICMP echo + TCP SYN simultaneously |
| SYN / ACK / NULL / FIN / Xmas | Raw TCP (`IP_RECVERR`) | Ephemeral lock | `IP_RECVERR` + Bind + Connect |
| UDP | `RAW TCP` | — | `IP_RECVERR` + Bind + Connect |
| Connect | `TCP SOCK_STREAM` | — | non  blocking socket + simultaneous `connect()` for each port |

---

## Threading Model

```mermaid
graph TB
    subgraph "Main Thread"
        ML[Main Loop<br />1 ms tick]
        WM[Worker Manager<br />assign · join · recycle]
        PR[Results Printer]
    end

    subgraph "Worker Pool  ─  max 250 threads"
        W1["Worker A<br />DNS host 4 (blocking, 1 task)"]
        W2["Worker B<br />Ping host 3 (1 task)"]
        W3["Worker C<br />SYN host 1 (16 ports)<br/>ACK host 2 (16 ports)<br/>UDP Host 2 (16 ports)<br/>(3 tasks, 2 hosts)"]
        W4["Worker D<br />UDP Host 1<br/>(1 task, 1 host)"]
        WN["Worker …"]
    end

    ML --> WM
    WM --> W1
    WM --> W2
    WM --> W3
    WM --> W4
    WM --> WN
    W1 & W2 & W3 & W4 & WN --> PR
```

Key rules:
- **DNS** and **Connect** tasks always get a dedicated worker (they block the thread).
- All other scan types share a worker; one worker may carry tasks for **different hosts** as long as scan types are compatible.
- An host cannot undergo 2 simultaneous TCP task (ping, SYN, ACK, NULL, FIN, XMAS, CONNECT) or 2 simultaneous UDP scan. But an host can undergo 2 simultanous scan of different type (TCP and UDP).

---

## Key Constants

| Constant | Value | Meaning |
|----------|-------|---------|
| `MAX_WORKER` | 250 | Maximum concurrent threads. Override with `--threads` option. |
| `MAX_TASK_WORKER` | 16 | Tasks per worker |
| `MAX_PORT_NBR` | 1024 | Ports scannable per run |
| `MAX_RETRIES` | 3 | Number of time a task is retried when cancelled |
| `PING_TIMEOUT` | 3 s | Ping phase hard timeout |
| `DFT_HOST_RTT` | 500 ms | RTT fallback when ping is skipped |
| `DFT_PORT_TIMEOUT_FACTOR` | 10× | Multiplier: RTT → probe timeout. Overridable with `--rtt-factor` option. |
| `DFT_MAX_RTT` | 3 000 ms | Maximum probe timeout cap. Overridable with `--rtt-max` option |

---

## Synchronisation

Two fields require atomic access because both the main thread and workers read/write them concurrently:

- `port_info.state` — written by worker, read by main thread after join (but declared `_Atomic` for correctness across retry paths)
- `worker_handle.state` — written by worker (`WORKER_DONE`), polled by main thread

All other host/scan data is accessed exclusively by the main thread while no worker holds a reference to it.