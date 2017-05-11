extern crate tls_parser;

use tls_parser::*;

#[macro_use] extern crate enum_primitive;
use enum_primitive::FromPrimitive;

pub fn main() {
    println!(r#"#ifndef __RUSTICATA_CIPHERSUITE_PARAMS__
#define __RUSTICATA_CIPHERSUITE_PARAMS__

// THIS FILE IS AUTO-GENERATED
// DO NOT EDIT IT

"#);

    // Kx ciphers
    println!("enum TlsCipherKx {{");
    for i in 0..255 {
        match TlsCipherKx::from_u8(i) {
            Some(kx) => println!("\tKx_{:?} = {},",kx,i),
            None => break,
        }
    }
    println!("}};\n");

    // Au ciphers
    println!("enum TlsCipherAu {{");
    for i in 0..255 {
        match TlsCipherAu::from_u8(i) {
            Some(au) => println!("\tAu_{:?} = {},",au,i),
            None => break,
        }
    }
    println!("}};\n");

    // Enc ciphers
    println!("enum TlsCipherEnc {{");
    for i in 0..255 {
        match TlsCipherEnc::from_u8(i) {
            Some(enc) => println!("\tEnc_{:?} = {},",enc,i),
            None => break,
        }
    }
    println!("}};\n");

    // EncMode ciphers
    println!("enum TlsCipherEncMode {{");
    for i in 0..255 {
        match TlsCipherEncMode::from_u8(i) {
            Some(encm) => println!("\tEncMode_{:?} = {},",encm,i),
            None => break,
        }
    }
    println!("}};\n");

    // Mac ciphers
    println!("enum TlsCipherMac {{");
    for i in 0..255 {
        match TlsCipherMac::from_u8(i) {
            Some(mac) => println!("\tMac_{:?} = {},",mac,i),
            None => break,
        }
    }
    println!("}};\n");

    // Exported constants
    println!(r#"

#define R_STATUS_EVENTS   0x0100

#define R_STATUS_OK       0x0000
#define R_STATUS_FAIL     0x0001

#define R_STATUS_EV_MASK  0x0f00
#define R_STATUS_MASK     0x00ff

#define R_STATUS_IS_OK(status) ((status & R_STATUS_MASK)==R_STATUS_OK)
#define R_STATUS_HAS_EVENTS(status) ((status & R_STATUS_EV_MASK)==R_STATUS_EVENTS)

"#);

    // Init functions
    println!(r#"
struct rust_config {{
	uint32_t magic;
	void *log;
	uint32_t log_level;
}};

extern int32_t rusticata_init(struct rust_config *);

"#);

    // Exported functions
    println!(r#"
struct _TlsParserState;
typedef struct _TlsParserState TlsParserState;

typedef uint32_t cipher_t;

extern uint32_t r_tls_probe(uint8_t *input, uint32_t input_len, uint32_t *offset);
extern uint32_t r_tls_parse(uint8_t direction, const unsigned char* value, uint32_t len, TlsParserState* state) __attribute__((warn_unused_result));

extern uint32_t r_tls_get_next_event(TlsParserState *state);

/* static methods */
extern uint32_t rusticata_tls_cipher_of_string(const char *s);
extern enum TlsCipherKx rusticata_tls_kx_of_cipher(uint16_t);
extern enum TlsCipherAu rusticata_tls_au_of_cipher(uint16_t);
extern enum TlsCipherEnc rusticata_tls_enc_of_cipher(uint16_t);
extern enum TlsCipherEncMode rusticata_tls_encmode_of_cipher(uint16_t);
extern enum TlsCipherMac rusticata_tls_mac_of_cipher(uint16_t);

/* TlsState methods */
extern uint32_t rusticata_tls_get_cipher(TlsParserState *state);
extern uint32_t rusticata_tls_get_dh_key_bits(TlsParserState *state);

// state functions
extern TlsParserState * r_tls_state_new(void);
extern void r_tls_state_free(TlsParserState *);

"#);


    println!("#endif // __RUSTICATA_CIPHERSUITE_PARAMS__");
}
