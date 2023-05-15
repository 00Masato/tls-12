// Ref: https://tex2e.github.io/rfc-translater/html/rfc5246.html#7-4-2--Server-Certificate
// opaque ASN.1Cert<1..2^24-1>;
//
// struct {
//     ASN.1Cert certificate_list<0..2^24-1>;
// } Certificate;
pub struct Certificate {
    pub certificate_list: Vec<u8>,
}