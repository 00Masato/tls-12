// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-3--Server-Key-Exchange-Message
// enum { dhe_dss, dhe_rsa, dh_anon, rsa, dh_dss, dh_rsa
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
// } KeyExchangeAlgorithm;
//
// struct {
//     opaque dh_p<1..2^16-1>;
//     opaque dh_g<1..2^16-1>;
//     opaque dh_Ys<1..2^16-1>;
// } ServerDHParams;     /* Ephemeral DH parameters */
//
// struct {
//     select (KeyExchangeAlgorithm) {
//         case dh_anon:
//             ServerDHParams params;
//         case dhe_dss:
//         case dhe_rsa:
//             ServerDHParams params;
//             digitally-signed struct {
//                 opaque client_random[32];
//                 opaque server_random[32];
//                 ServerDHParams params;
//             } signed_params;
//         case rsa:
//         case dh_dss:
//         case dh_rsa:
//     struct {} ;
//     /* message is omitted for rsa, dh_dss, and dh_rsa */
//     /* may be extended, e.g., for ECDH -- see [TLSECC] */
//     };
// } ServerKeyExchange;

pub struct ServerKeyExchange {
    pub params: Vec<u8>,
}