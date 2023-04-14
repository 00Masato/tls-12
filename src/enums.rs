// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7--The-TLS-Handshaking-Protocols

// enum { warning(1), fatal(2), (255) } AlertLevel;
pub enum AlertLevel {
    Warning,
    Fatal,
}

// enum {
//           close_notify(0),
//           unexpected_message(10),
//           bad_record_mac(20),
//           decryption_failed_RESERVED(21),
//           record_overflow(22),
//           decompression_failure(30),
//           handshake_failure(40),
//           no_certificate_RESERVED(41),
//           bad_certificate(42),
//           unsupported_certificate(43),
//           certificate_revoked(44),
//           certificate_expired(45),
//           certificate_unknown(46),
//           illegal_parameter(47),
//           unknown_ca(48),
//           access_denied(49),
//           decode_error(50),
//           decrypt_error(51), export_restriction_RESERVED(60),
//           protocol_version(70),
//           insufficient_security(71),
//           internal_error(80),
//           user_canceled(90),
//           no_renegotiation(100),
//           unsupported_extension(110),
//           (255)
//       } AlertDescription;
pub enum AlertDescription {
    CloseNotify,
    UnexpectedMessage,
    BadRecordMac,
    DecryptionFailed,
    RecordOverflow,
    DecompressionFailure,
    HandshakeFailure,
    NoCertificateReserved,
    BadCertificate,
    UnsupportedCertificate,
    CertificateRevoked,
    CertificateExpired,
    CertificateUnknown,
    IllegalParameter,
    UnknownCa,
    AccessDenied,
    DecodeError,
    DecryptError,
    ExportRestrictionReserved,
    ProtocolVersion,
    InsufficientSecurity,
    InternalError,
    UserCanceled,
    NoRenegotiation,
    UnsupportedExtension,
}


// enum {
//           hello_request(0), client_hello(1), server_hello(2),
//           certificate(11), server_key_exchange (12),
//           certificate_request(13), server_hello_done(14),
//           certificate_verify(15), client_key_exchange(16),
//           finished(20), (255)
//       } HandshakeType;
pub enum HandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
}