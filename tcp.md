# TCP with RAW sockets

To send TCP packet : 

```C
fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
```


~~~
A raw socket can be bound to a specific local address using the bind() call.   If it isn't bound, all packets with the specified IP protocol are received.  In addition a RAW socket can be bound to a specific network device using SO_BINDTODEVICE (check the socket() man page). 
~~~

~~~
An IPPROTO_RAW socket is send only.  If you really want to receive all IP packets use a packet() socket with the ETH_P_IP protocol.  Note that packet sockets don't reassemble IP fragments, unlike raw sockets. 
If you want to receive all ICMP packets for a datagram socket it is often better to use IP_RECVERR on that particular socket.

https://stackoverflow.com/questions/13087097/how-to-get-icmp-on-udp-socket-on-unix
https://stackoverflow.com/questions/11914568/read-icmp-payload-from-a-recvmsg-with-msg-errqueue-flag
~~~

## Connecting a mock UDP socket to lock a port

We can send a TCP packet through any RAW socket (whether its a TCP RAW socket or an ICMP RAW socket).
But to compute the pseudo-iphdr checksum of our outgoing packet, we need :
- to know the local ip address from which our packet will be outbounded
- to define a TCP source port, free if possible, to avoid any collision with existing socket.

A way to enforce an available source port and to know the local ip address is to create a UDP socket and connect it to the target address :

```C
udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
if (udp_sock < 0)
	return (-1);
if (connect(udp_sock, dest, dest_len) < 0) {
	return (-1);
}
if (getsockname(udp_sock, (struct sockaddr *)saddr, &s_saddr_len) <
	0)
	return (-1);
packet->port_out = ntohs(saddr->sin_port);
packet->udp_sock = udp_sock;
printf("got address = %s and port = %hu\n", inet_ntoa(saddr->sin_addr),
		packet->port_out);
return (0);
```

## What happens if we choose an already used TCP/UDP port ?

Any opened TCP-RAW socket will still receive incoming packet, but another application may receive packets unrelated to its normal flow and it may cause undefined behaviour. However such a situation will only happen if the application use an unconnected socket binded to the same port we are using.

## What about ICMP error ?

ICMP message are not directly associated to a source or destination port, although it may be possible in most of the situation to infere on which socket came the message from which originated the ICMP error.

### Using RAW ICMP socket

A way to receive ICMP error related to the TCP packet we sent would be to use a RAW ICMP socket to intercept every ICMP error and filter the one that originated from our process, and then associate them as answers to our probes.
This require root privilege.

```C
icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
```

### Use a single UDP socket by peer with IP_RCVERR enabled ?

This would limit the simultaneous probe limit to 1024 if a single process used.
This would not require root privilege.

**Not possible** : opening a `SOCK_DGRAM` prevent access to ip header, so the protocol field in the header cannot be enforced.

**From TCP/IP Illustrated Volume 2, p. 769-770**
~~~
ICMP Errors and UDP Sockets
One confusing part of the sockets API is that ICMP errors received on a UDP socket are not passed to
the application unless the application has issued a connect on the socket, restricting the foreign IP
address and port number for the socket. We now see where this limitation is enforced by
in_pcbnotify.
Consider an ICMP port unreachable, probably the most common ICMP error on a UDP socket. The
foreign IP address and the foreign port number in the dst argument to in_pcbnotify are the
IP address and port number that caused the ICMP error. But if the process has not issued a
connect on the socket, the inp_faddr and inp_fport members of the PCB are both 0,
preventing in_pcbnotify from ever calling the notify function for this socket. The for
loop in Figure 22.33 will skip every UDP PCB.
This limitation arises for two reasons. First, if the sending process has an unconnected UDP socket,
the only nonzero element in the socket pair is the local port. (This assumes the process did not call
bind.) This is the only value available to in_pcbnotify to demultiplex the incoming ICMP
error and pass it to the correct process. Although unlikely, there could be multiple processes bound to
770
the same local port, making it ambiguous which process should receive the error. There’s also the
possibility that the process that sent the datagram that caused the ICMP error has terminated, with
another process then starting and using the same local port. This is also unlikely since ephemeral ports
are assigned in sequential order from 1024 to 5000 and reused only after cycling around (Figure
22.23).
The second reason for this limitation is because the error notification from the kernel to the process
an errno value is inadequate. Consider a process that calls sendto on an unconnected UDP
socket three times in a row, sending a UDP datagram to three different destinations, and then waits for
the replies with recvfrom. If one of the datagrams generates an ICMP port unreachable error, and
if the kernel were to return the corresponding error (ECONNREFUSED) to the recvfrom that the
process issued, the errno value doesn’t tell the process which of the three datagrams caused the
error. The kernel has all the information required in the ICMP error, but the sockets API doesn’t
provide a way to return this to the process.
Therefore the design decision was made that if a process wants to be notified of these ICMP errors on
a UDP socket, that socket must be connected to a single peer. If the error ECONNREFUSED is
returned on that connected socket, there’s no question which peer generated the error.
There is still a remote possibility of an ICMP error being delivered to the wrong process. One process
sends the UDP datagram that elicits the ICMP error, but it terminates before the error is received.
Another process then starts up before the error is received, binds the same local port, and connects to
the same foreign address and foreign port, causing this new process to receive the error. There’s no
way to prevent this from occurring, given UDP’s lack of memory. We’ll see that TCP handles this with
its TIME_WAIT state.
In our preceding example, one way for the application to get around this limitation is to use three
connected UDP sockets instead of one unconnected socket, and call select to determine when any one
of the three has a received datagram or an error to be read.
Here we have a scenario where the kernel has the information but the API (sockets)
is inadequate. With most implementations of Unix System V and the other popular
API (TLI), the reverse is true: the TLI function t_rcvuderr can return the peer’s
IP address, port number, and an error value, but most SVR4 streams implementations
of TCP/IP don’t provide a way for ICMP to pass the error to an unconnected UDP
end point.
In an ideal world, in_pcbnotify delivers the ICMP error to all UDP sockets
that match, even if the only nonwildcard match is the local port. The error returned to
the process would include the destination IP address and destination UDP port that
caused the error, allowing the process to determine if the error corresponds to a
datagram sent by the process.
~~~

### Using a bounded+connected TCP RAW_SOCKET with IP_RECVERR enabled

Then a single socket could be associated with a single host.
Still the limit of max 1024 sockets (or 512 when locking ephemeral ports).

- **Can a raw socket be bounded ?** Yes.
- **What's the reason to be bind a raw socket ?** To filter packet intended for a specific local address.
- **Can a raw socket be connected ?** Yes.
- **What's the reason to connect a raw socket ?** To allow the kernel's API to redirect ICMP error related to the socket and to filter incoming TCP packet.
- **Can a raw socket can receive both TCP and ICMP respone ?** Yes, if we use declare it as TCP and we enable IP_RECVERR, it also requires to use `poll()` instead of `select()` in order to detect ICMP errors on socket.
- **Can a single socket send packet to multiple peer ?** Yes.
  - **Will this packet receive ICMP error from multiple hosts (if IP_RECVERR enabled) ?** No, because the kernel API infere the socket where the error originated from using the peer adress off the original paquet. So the socket needs to be connected to this address.
- **How to choose the outbound port when sending TCP packet via a RAW socket ?** By opening a UDP/TCP socket and binding it to an ephemeral port. The socket can be closed and the port released when the RAW socket is closed. This uses 2 socket/scan instead of 1 so the limit for a single process is 512 simultaneous hosts.

For UDP scan method :
- we can use either UDP unprivileged socket with IP_RECVERR option
- we can use use bounded+connected RAW socket with UDP and ICMP protocol 

# Questions

## Can a RAW-TCP socket (binded + connected + IP_RECVERR) interact with multiple port at once ?

Yes.
So a 

## Can a UDP socket (binded + connected + IP_RECVERR) interact with multiple port at once ?

Not sure.