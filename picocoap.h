///
/// @file	 coap.h
/// @author	 Patrick Barrett <patrickbarrett@exosite.com>
/// @date	 2014-07-10
/// @brief	 CoAP Message Parsing
///
/// @details This file provides functions for parsing and building CoAP message packets
///          using only the actual binary of the message, not needing additional memory
///          for secondary data structures.
///

#ifndef _COAP_H_
#define _COAP_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stddef.h>
#include <stdint.h>


///
/// CoAP Defined Parameters
///
#define COAP_ACK_TIMEOUT          2
#define COAP_ACK_RANDOM_FACTOR    1.5
#define COAP_MAX_RETRANSMIT       4
#define COAP_NSTART               1
#define COAP_DEFAULT_LEISURE      5
#define COAP_PROBING_RATE         1

#define COAP_MAX_TRANSMIT_SPAN   45
#define COAP_MAX_TRANSMIT_WAIT   93
#define COAP_MAX_LATENCY        100
#define COAP_PROCESSING_DELAY     2
#define COAP_MAX_RTT            202
#define COAP_EXCHANGE_LIFETIME  247
#define COAP_NON_LIFETIME       145

// total number of CoAP options available
#define COAP_OPTIONS_LENGTH		16

/*
 * this struct and the corresponding names are added
 * so we can check the fields in the SCHC header
 */
struct pcoap_option_names {
	uint16_t id;
	char name[16];
};

static struct pcoap_option_names coap_options[COAP_OPTIONS_LENGTH] = {
		{ 1, "if-match" },
		{ 3, "uri-host" },
		{ 4, "etag" },
		{ 5, "if-none-match" },
		{ 7, "uri-port" },
		{ 8, "location-path" },
		{ 11, "uri-path"} ,
		{ 12, "content-format" },
		{ 14, "max-age" },
		{ 15, "uri-query" },
		{ 17, "accept" },
		{ 20, "location-query" },
		{ 35, "proxy-uri" },
		{ 39, "proxy-scheme" },
		{ 60, "size1" },
		{ 258, "no-response"}
};

///
/// Status Codes
///
/// These codes represent the possible errors that functions in this library can
/// return.
///
typedef enum coap_error {
	CE_NONE = 0,
	CE_INVALID_PACKET,
	CE_BAD_VERSION,
	CE_TOKEN_LENGTH_OUT_OF_RANGE,
	CE_UNKNOWN_CODE,
	CE_TOO_MANY_OPTIONS,
	CE_OUT_OF_ORDER_OPTIONS_LIST,
	CE_INSUFFICIENT_BUFFER,
	CE_FOUND_PAYLOAD_MARKER,
	CE_END_OF_PACKET
} pcoap_error;

///
/// Protocol Versions
///
/// All known version of the protocol.
///
typedef enum coap_version {
	COAP_V1 = 1
} pcoap_version;

///
/// Message Types
///
/// The four types of messages possible.
///
typedef enum coap_type {
	CT_CON = 0,
	CT_NON = 1,
	CT_ACK = 2,
	CT_RST = 3
} pcoap_type;

///
/// Message Codes
///
/// All known message request/response codes.
///
typedef enum pcoap_code {
	/* CoAP method codes */
	CC_EMPTY = 0,
	CC_GET = 1,
	CC_POST = 2,
	CC_PUT = 3,
	CC_DELETE = 4,
	/* CoAP response codes */
	CC_CREATED = 65,
	CC_DELETED = 66,
	CC_VALID = 67,
	CC_CHANGED = 68,
	CC_CONTENT = 69,
	CC_CONTINUE = 95,
	CC_BAD_REQUEST = 128,
	CC_UNAUTHORIZED = 129,
	CC_BAD_OPTION = 130,
	CC_FORBIDDEN = 131,
	CC_NOT_FOUND = 132,
	CC_METHOD_NOT_ALLOWED = 133,
	CC_NOT_ACCEPTABLE = 134,
	CC_REQUEST_ENTITY_INCOMPLETE = 136,
	CC_PRECONDITION_FAILED = 140,
	CC_REQUEST_ENTITY_TOO_LARGE = 141,
	CC_UNSUPPORTED_CONTENT  = 143,
	CC_INTERNAL_SERVER_ERROR = 160,
	CC_NOT_IMPLEMENTED = 161,
	CC_BAD_GATEWAY = 162,
	CC_SERVICE_UNAVAILABLE = 163,
	CC_GATEWAY_TIMEOUT = 164,
	CC_PROXYING_NOT_SUPPORTED = 165
} pcoap_code;

///
/// Option Numbers
///
/// All known option numbers.
///
typedef enum pcoap_option_number {
	CON_IF_MATCH = 1,
	CON_URI_HOST = 3,
	CON_ETAG = 4,
	CON_IF_NONE_MATCH = 5,
	CON_OBSERVE = 6,
	CON_URI_PORT = 7,
	CON_LOCATION_PATH = 8,
	CON_URI_PATH = 11,
	CON_CONTENT_FORMAT = 12,
	CON_MAX_AGE = 14,
	CON_URI_QUERY = 15,
	CON_ACCEPT = 17,
	CON_LOCATION_QUERY = 20,
	CON_PROXY_URI = 35,
	CON_PROXY_SCHEME = 39,
	CON_SIZE1 = 60,
	CON_NO_RESPONSE = 258
} pcoap_option_number;

///
/// Packet Data Unit
///
/// This contains all information about the message buffer.
///
typedef struct pcoap_pdu {
	uint8_t *buf;  /// pointer to buffer
	size_t len;	   /// length of current message
	size_t max;	   /// size of buffer
} pcoap_pdu;

///
/// CoAP Option
///
/// One option in a CoAP message.
///
typedef struct pcoap_option {
	uint16_t num;	/// size of buffer
	size_t len;	/// length of the value
	uint8_t *val;	/// pointer value
} pcoap_option;

///
/// CoAP Payload
///
/// Payload container.
///
typedef struct pcoap_payload {
	size_t len;	/// length of current message
	uint8_t *val;	/// pointer to buffer
} pcoap_payload;

// Finds the length of the CoAP header
// And consequently the length of the payload
uint8_t pcoap_get_coap_offset(pcoap_pdu *pdu);

///
/// Validate Packet
///
/// Parses the given packet to check if it is a valid CoAP message.
/// This function (or coap_init_pdu for creating new packets) must be
/// called and must return CE_NONE before you can use any of the
/// getters or setter.
/// @param  [in] pdu pointer to the coap message struct.
/// @return error code (CE_NONE == 0 == no error).
/// @see    coap_error
/// @see    coap_init_pdu
///
pcoap_error pcoap_validate_pkt(pcoap_pdu *pdu);

//
// Getters
//

///
/// Get Version
///
/// Extracts the CoAP version from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return version.
/// @see coap_version
///
static inline pcoap_version pcoap_get_version(pcoap_pdu *pdu) { return (pcoap_version) (pdu->buf[0] >> 6); }

///
/// Get Message Type
///
/// Extracts the message type from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return type.
/// @see coap_type
///
static inline pcoap_type pcoap_get_type(pcoap_pdu *pdu) { return (pcoap_type) ((pdu->buf[0] >> 4) & 0x03); }

///
/// Get Token Length
///
/// Extracts the token length from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return length.
/// @see coap_type
///
static inline uint8_t pcoap_get_tkl(pcoap_pdu *pdu) { return pdu->buf[0] & 0x0F; }

///
/// Get Message Code
///
/// Extracts the message code from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return code.
/// @see coap_code
///
static inline pcoap_code pcoap_get_code(pcoap_pdu *pdu) { return (pcoap_code) (pdu->buf[1]); }

///
/// Get Message Code Class
///
/// Gets the class portion of the message code.
/// @param  [in] pdu pointer to the coap message struct.
/// @see    coap_get_code
///
static inline uint8_t pcoap_get_code_class(pcoap_pdu *pdu) { return pcoap_get_code(pdu) >> 5; }

///
/// Get Message Code Detail
///
/// Gets the detail portion of the message code.
/// @param  [in] pdu pointer to the coap message struct.
/// @see    coap_get_code
///
static inline uint8_t pcoap_get_code_detail(pcoap_pdu *pdu) { return pcoap_get_code(pdu) & 0x1F; }

///
/// Get Message ID
///
/// Extracts the message ID from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return mid.
///
static inline uint16_t pcoap_get_mid(pcoap_pdu *pdu) { return (pdu->buf[2] << 8) | pdu->buf[3]; }

///
/// Get Message Token
///
/// Extracts the token from the given message.
/// @param  [in] pdu pointer to the coap message struct.
/// @return token.
///
uint8_t pcoap_get_token(pcoap_pdu *pdu, uint8_t* ptr);

///
/// Get Option
///
/// Iterates over the options in the given message.
/// @param  [in]  pdu  pointer to the coap message struct.
/// @param  [in, out]  pointer to the last/next option, pass
///                    0 for the first option.
/// @return coap_option
///
pcoap_option pcoap_get_option(pcoap_pdu *pdu, pcoap_option *last);

///
/// Get Option by Option Number
///
/// Gets a single specified by the option number and index of which occurrence
/// of that option number you'd like.
/// @param  [in]  pdu  pointer to the coap message struct.
/// @param  [in]  num  option number to get.
/// @param  [in]  occ  occurrence of to get (0th, 1st, 2nd, etc)
///                    0 for the first option.
/// @return coap_option
///
pcoap_option pcoap_get_option_by_num(pcoap_pdu *pdu, pcoap_option_number num, uint8_t occ);

///
/// Get Option
///
/// Extracts the option with the given index in the given message.
/// @param  [in]  pdu    pointer to the coap message struct.
/// @return coap_payload
///
pcoap_payload pcoap_get_payload(pcoap_pdu *pdu);

///
/// Internal Method
///
pcoap_error pcoap_decode_option(uint8_t *pkt_ptr, size_t pkt_len,
	                          uint16_t *option_number, size_t *option_length, uint8_t **value);

//
// Setters
//

///
/// Initialize Packet
///
/// Initializes on an empty buffer for creating new CoAP packets.
/// This function (or coap_validate for parsing packets) must be
/// called and must return CE_NONE before you can use any of the
/// getters or setter. The packet is initialized to a CoAP Ping.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @return coap_error (0 == no error)
///
pcoap_error pcoap_init_pdu(pcoap_pdu *pdu);

///
/// Set Version
///
/// Sets the version number header field.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @param  [in]      ver      version to set. Must be COAP_V1.
/// @return coap_error (0 == no error)
/// @see coap_version
///
pcoap_error pcoap_set_version(pcoap_pdu *pdu, pcoap_version ver);

///
/// Set Message Type
///
/// Sets the message type header field.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @param  [in]      mtype    type to set.
/// @return coap_error (0 == no error)
/// @see coap_type
///
pcoap_error pcoap_set_type(pcoap_pdu *pdu, pcoap_type mtype);

///
/// Set Message Code
///
/// Sets the message type header field.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @param  [in]      code     code to set.
/// @return coap_error (0 == no error)
/// @see coap_code
///
pcoap_error pcoap_set_code(pcoap_pdu *pdu, pcoap_code code);

///
/// Set Message ID
///
/// Sets the message ID header field.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @param  [in]      mid      message ID to set.
/// @return coap_error (0 == no error)
///
pcoap_error pcoap_set_mid(pcoap_pdu *pdu, uint16_t mid);

///
/// Set Message Token
///
/// Sets the message token header field.
/// @param  [in, out] pdu pointer to the coap message struct.
/// @param  [in]      token    pointer to the token array to set.
/// @return coap_error (0 == no error)
///
pcoap_error pcoap_set_token(pcoap_pdu *pdu, uint8_t* token, uint8_t tkl);

///
/// Add Message Option
///
/// Adds an option to the existing message. Options SHOULD be added in order of
/// option number. In the case of multiple options of the same type, they are 
/// sorted in the order that they are added.
/// @param  [in, out] pdu  pointer to the coap message struct.
/// @param  [in]      opt  option container.
/// @return coap_error (0 == no error)
///
pcoap_error pcoap_add_option(pcoap_pdu *pdu, int32_t opt_num, uint8_t* value, uint16_t opt_len);

///
/// Add Message Option
///
/// Sets the payload of the given message to the value in `payload`.
/// @param  [in, out] pdu  pointer to the coap message struct.
/// @param  [in]      pl   payload container.
/// @return coap_error (0 == no error)
///
pcoap_error pcoap_set_payload(pcoap_pdu *pdu, uint8_t *payload, size_t payload_len);

///
/// Build Message Code from Class and Detail
///
/// Gets the class portion of the message code.
/// @param  [in]  class  the code class.
/// @param  [in]  detail the code detail.
/// @see    coap_get_code
///
static inline uint8_t pcoap_build_code(uint8_t _class, uint8_t detail) { return (_class << 5) | detail; }

//
// Internal
//

///
/// Internal Method
///
pcoap_error pcoap_adjust_option_deltas(uint8_t *opts, size_t *opts_len, size_t max_len, int32_t offset);

///
/// Internal Method
///
int8_t pcoap_build_option_header(uint8_t *buf, size_t max_len, int32_t opt_delta, int32_t opt_len);

///
/// Internal Method
///
int8_t pcoap_compute_option_header_len(int32_t opt_delta, int32_t opt_len);

#ifdef __cplusplus
}
#endif

#endif /*_COAP_H_*/

