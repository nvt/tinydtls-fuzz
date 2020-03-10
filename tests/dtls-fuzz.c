/*
This is a fuzzing harness for TinyDTLS. It read data from files provided
as command line parameters and feeds the data to the DTLS library.
In doing so, it basically bypasses (UDP) sockets. 

*/


/* This is needed for apple */
#define __APPLE_USE_RFC_3542

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <signal.h>

#include "tinydtls.h" 
#include "dtls.h" 

#define LOG_MODULE "dtls-server"
#define LOG_LEVEL  LOG_LEVEL_DTLS
#include "dtls-log.h"

#define DEFAULT_PORT 20220
#define READ_MAX_BUFF 2000
#define MAX_FILENAME_LEN 100

#define PSK_HANDSHAKE_FOLDER "handshakes/psk"
#define ECC_HANDSHAKE_FOLDER "handshakes/ecc"

static const unsigned char ecdsa_priv_key[] = {
			0xD9, 0xE2, 0x70, 0x7A, 0x72, 0xDA, 0x6A, 0x05,
			0x04, 0x99, 0x5C, 0x86, 0xED, 0xDB, 0xE3, 0xEF,
			0xC7, 0xF1, 0xCD, 0x74, 0x83, 0x8F, 0x75, 0x70,
			0xC8, 0x07, 0x2D, 0x0A, 0x76, 0x26, 0x1B, 0xD4};

static const unsigned char ecdsa_pub_key_x[] = {
			0xD0, 0x55, 0xEE, 0x14, 0x08, 0x4D, 0x6E, 0x06,
			0x15, 0x59, 0x9D, 0xB5, 0x83, 0x91, 0x3E, 0x4A,
			0x3E, 0x45, 0x26, 0xA2, 0x70, 0x4D, 0x61, 0xF2,
			0x7A, 0x4C, 0xCF, 0xBA, 0x97, 0x58, 0xEF, 0x9A};

static const unsigned char ecdsa_pub_key_y[] = {
			0xB4, 0x18, 0xB6, 0x4A, 0xFE, 0x80, 0x30, 0xDA,
			0x1D, 0xDC, 0xF4, 0xF4, 0x2E, 0x2F, 0x26, 0x31,
			0xD0, 0x43, 0xB1, 0xFB, 0x03, 0xE2, 0x2F, 0x4D,
			0x17, 0xDE, 0x43, 0xF9, 0xF9, 0xAD, 0xEE, 0x70};

#if 0
/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum) {
  dsrv_stop(dsrv_get_context());
}
#endif

#ifdef DTLS_PSK
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identity within this particular
 * session. */
static int
get_psk_info(struct dtls_context_t *ctx, const session_t *session,
	     dtls_credentials_type_t type,
	     const unsigned char *id, size_t id_len,
	     unsigned char *result, size_t result_length) {
  switch(type) {
    case DTLS_PSK_KEY:

    memcpy(result, (unsigned char *)"\x12\x34", 2);
    return 2;

    case DTLS_PSK_IDENTITY:
      memcpy(result,(unsigned char *) "Client_identity", 15);
      return 15;
    default: 
      return 0; 
  }
}

#endif /* DTLS_PSK */

#ifdef DTLS_ECC
static int
get_ecdsa_key(struct dtls_context_t *ctx,
	      const session_t *session,
	      const dtls_ecdsa_key_t **result) {
  static const dtls_ecdsa_key_t ecdsa_key = {
    .curve = DTLS_ECDH_CURVE_SECP256R1,
    .priv_key = ecdsa_priv_key,
    .pub_key_x = ecdsa_pub_key_x,
    .pub_key_y = ecdsa_pub_key_y
  };

  *result = &ecdsa_key;
  return 0;
}

static int
verify_ecdsa_key(struct dtls_context_t *ctx,
		 const session_t *session,
		 const unsigned char *other_pub_x,
		 const unsigned char *other_pub_y,
		 size_t key_size) {
  return 0;
}
#endif /* DTLS_ECC */

#define DTLS_SERVER_CMD_CLOSE "server:close"
#define DTLS_SERVER_CMD_RENEGOTIATE "server:renegotiate"

static void
add_peer(dtls_peer_t **peers, dtls_peer_t *peer)
{
  peer->next = *peers;
  *peers = peer;
}

static int
dtls_add_peer(dtls_context_t *ctx, dtls_peer_t *peer) {
  if(peer) {
    // add_peer(&ctx->peers, peer);
  }
  return 0;
}

static int
read_from_peer(struct dtls_context_t *ctx, 
	       session_t *session, uint8_t *data, size_t len) {
  size_t i;
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  if (len >= strlen(DTLS_SERVER_CMD_CLOSE) &&
      !memcmp(data, DTLS_SERVER_CMD_CLOSE, strlen(DTLS_SERVER_CMD_CLOSE))) {
    printf("server: closing connection\n");
    dtls_close(ctx, session);
    return len;
  } else if (len >= strlen(DTLS_SERVER_CMD_RENEGOTIATE) &&
      !memcmp(data, DTLS_SERVER_CMD_RENEGOTIATE, strlen(DTLS_SERVER_CMD_RENEGOTIATE))) {
    printf("server: renegotiate connection\n");
    dtls_renegotiate(ctx, session);
    return len;
  }

  return dtls_write(ctx, session, data, len);
}

// sending is always successful 
static int
send_to_peer(struct dtls_context_t *ctx, 
	     session_t *session, uint8_t *data, size_t len) {
  dtls_debug_hexdump("sending", data, len);
  return len;
}

// we populate the address with valid data so that it passes checks
void populate_sockaddr(struct sockaddr_in *sa) {
  sa->sin_family = AF_INET;
  sa->sin_port = htons(55555);
  sa->sin_addr.s_addr = inet_addr("127.0.0.1");
}

// populate peer details
void populate_peer(struct dtls_context_t *ctx, session_t* session) {
  dtls_peer_t *peer;
  dtls_handshake_parameters_t *handshake_params;
  handshake_params = dtls_handshake_new();
  handshake_params->hs_state.mseq_s = 1;
  handshake_params->hs_state.mseq_r = 0;
  handshake_params->compression = TLS_COMPRESSION_NULL;
  handshake_params->cipher = TLS_NULL_WITH_NULL_NULL;
  handshake_params->do_client_auth = 0;
  strcpy(handshake_params->keyx.psk.identity, "Client_identity");
  handshake_params->keyx.psk.id_length = 15;

  peer = dtls_new_peer(session);
  peer->role = DTLS_CLIENT;
  peer->state = DTLS_STATE_CLIENTHELLO;
  peer->handshake_params = handshake_params;
  if (dtls_add_peer(ctx, peer) < 0) {
    dtls_alert("cannot add peer\n");
  }
}

static uint8_t start_rec [] = {0x16, 0xfe, 0xfd};
static size_t start_rec_len = 3;

static int
dtls_handle_read(struct dtls_context_t *ctx, uint8_t *buf, int len, int IS_SERVER) {
  int *fd;
  session_t session;
  dtls_peer_t *peer;

  fd = dtls_get_app_data(ctx);

  assert(fd);

  memset(&session, 0, sizeof(session_t));
  session.size = sizeof(session.addr);
  populate_sockaddr((struct sockaddr_in *)&session.addr.sa);


  if (len < 0) {
    perror("fread");
    return -1;
  } else {
    dtls_debug("got %d bytes from fake port %d\n", len, 
	     ntohs(session.addr.sin6.sin6_port));
    if (sizeof(buf) < len) {
      dtls_warn("packet was truncated (%d bytes lost)\n", (int)(len - sizeof(buf)));
    }
  }

  return dtls_handle_message(ctx, &session, buf, len);
}    

static dtls_handler_t cb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
};

static dtls_handler_t sb = {
  .write = send_to_peer,
  .read  = read_from_peer,
  .event = NULL,
#ifdef DTLS_PSK
  .get_psk_info = get_psk_info,
#endif /* DTLS_PSK */
#ifdef DTLS_ECC
  .get_ecdsa_key = get_ecdsa_key,
  .verify_ecdsa_key = verify_ecdsa_key
#endif /* DTLS_ECC */
};

int fuzz_file(const uint8_t *record, size_t size, char* crypt, int packet_order){
  dtls_context_t *the_server_context = NULL;
  dtls_context_t *the_client_context = NULL;
  fd_set rfds, wfds;
  struct timeval timeout;
  int fd=100, opt, result;
  FILE *f = NULL;
  static uint8_t buf[READ_MAX_BUFF];
  char file_name[MAX_FILENAME_LEN], base_name[MAX_FILENAME_LEN];
  int on = 1, no_of_msg = 0, len = 0;
    
  
  if(strcmp(crypt, "psk") == 0){
    sprintf(base_name, "%s/", PSK_HANDSHAKE_FOLDER);
    no_of_msg = 10;
  }
  else if(strcmp(crypt, "ecc") == 0){
    sprintf(base_name, "%s/", ECC_HANDSHAKE_FOLDER);
    no_of_msg = 15;
  }
  else {
    dtls_alert("Invalid crypt value: Use \"psk\" or \"ecc\"\n");
    return 0;
  }

  dtls_init();
  the_server_context = dtls_new_context(&fd);
  dtls_set_handler(the_server_context, &sb);

  the_client_context = dtls_new_context(&fd);
  dtls_set_handler(the_client_context, &cb);
  // FILE* writeFile = fopen("RESULT.txt", "a");
  
  for (int i=0; i<no_of_msg; i++) {
    sprintf(file_name, "%s%d", base_name, i);
    
    if(i != packet_order){
      f = fopen(file_name, "rb");
      len = fread(buf, sizeof *buf, READ_MAX_BUFF, f);
      fclose(f);
      
      if (f == NULL) {
          dtls_alert("Couldn't open %s\n", file_name);
          break;
      }
      f = NULL;
    } else {
        memcpy(buf, record, size+1);
        len = size;
    }

    if(i == 0){
      session_t session;
      memset(&session, 0, sizeof(session_t));
      session.size = sizeof(session.addr);
      populate_sockaddr((struct sockaddr_in *)&session.addr.sa);
      dtls_connect(the_client_context, &session);
      populate_peer(the_client_context, &session);
    }

    // fprintf(writeFile, "/////////////////// %s ///////////////\n", argv[i+1]);
    // printf("/////////////////// %s ///////////////\n", argv[i+1]);
    // if(strncmp(argv[i+1]+strlen(argv[i+1])-1, "s", 1) == 0){
    //   result = dtls_handle_read(the_client_context, f, 0);
    // } else {
    //   result = dtls_handle_read(the_server_context, f, 1);
    // }
    printf("Iteration %d\n",i);
    switch (i)
    {
      case 0:
      case 2:
      case 5:
      case 6:
      case 7:
        result = dtls_handle_read(the_server_context, buf, len, 1);
        break;
      case 1:
      case 3:
      case 4:
      case 8:
      case 9:
        result = dtls_handle_read(the_client_context, buf, len, 0);
        break;
    
      default:
        break;
    }

    if(result){
      char *response = "Couldn't handle message\n";
      // strcat( response, argv[i+1]);
      // strcat( response, "\n");
      
      dtls_alert(response);
      //break;
    }
  }

 error:
  if (f != NULL) {
    fclose(f);
  }

  dtls_free_context(the_server_context);
  dtls_free_context(the_client_context);
  return 0;
}


int main(int argc, char **argv) {
  FILE *f = NULL;
  static uint8_t buf[READ_MAX_BUFF];
  char *crypt;
  int packet_order = -1, len = 0;
  #undef DTLS_ECC
  if (argc != 2 && argc != 4) {
      dtls_alert("Usage: dtls_fuzz packet_file psk/ecc [packet_order]\n");
      return 0;
  }
    
  if(argc == 4){
    packet_order = atoi(argv[3]);
    crypt = argv[2];
  }
  else {
    const char s[] = ",";
    char *token, *file_order, *filename;
    filename = argv[1];
    
    /* get the first token */
    token = strtok(filename, s);
    
    /* walk through other tokens */
    while( token != NULL ) {
      crypt = file_order;
      file_order = token;
      token = strtok(NULL, s);
    }
    packet_order = atoi(file_order);
  }

  f = fopen(argv[1], "rb");
  len = fread(buf, sizeof *buf, READ_MAX_BUFF, f);
  fclose(f);

  fuzz_file(buf, len, crypt, packet_order);

 error:
  if (!f) {
    fclose(f);
  }

  exit(0);
}