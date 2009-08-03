#ifndef __HOOK_P0F_H
#define __HOOK_P0F_H

// p0f 2.0.5. Added P<zero>F 

#define P0F_MAX_SOCK_SIZE 100 // actually it's 104

#define P0F_RESP_OK         0       /* Response OK */
#define P0F_RESP_BADQUERY   1       /* Query malformed */
#define P0F_RESP_NOMATCH    2       /* No match for src-dst data */
#define P0F_QUERY_MAGIC             0x0defaced

// p0f typedefs
typedef unsigned char           _u8;
typedef unsigned short          _u16;
typedef unsigned int            _u32;
typedef signed char             _s8;
typedef signed short            _s16;
typedef signed int              _s32;

struct p0f_query {
  _u32 magic;                   /* must be set to QUERY_MAGIC */
  _u32 id;                      /* Unique query ID */
  _u32 src_ad,dst_ad;           /* src address, local dst addr */
  _u16 src_port,dst_port;       /* src and dst ports */
};

struct p0f_response {
  _u32 magic;                   /* QUERY_MAGIC */
  _u32 id;                      /* Query ID (copied from p0f_query) */
  _u8  type;                    /* RESP_* */
  _u8  genre[20];               /* OS genre (empty if no match) */
  _u8  detail[40];              /* OS version (empty if no match) */
  _s8  dist;                    /* Distance (-1 if unknown ) */
  _u8  link[30];                /* Link type (empty if unknown) */
  _u8  tos[30];                 /* Traffic type (empty if unknown) */
  _u8  fw,nat;                  /* firewall and NAT flags flags */
  _u8  real;                    /* A real operating system? */
  _s16 score;                   /* Masquerade score (or NO_SCORE) */
  _u16 mflags;                  /* Masquerade flags (D_*) */
  _s32 uptime;                  /* Uptime in hours (-1 = unknown) */
};

int hook_p0f(struct signature *sig,struct traffic *traffic);
int hook_p0f_options(char *key, char *val, struct signature *sig);
int p0f_connect_socket();
int p0f_disconnect_socket();
int p0f_query(TcpSession *tsess);

#endif
