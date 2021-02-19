#include "crypto.h"

#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace sframe {

struct RAIILog {
  RAIILog(std::string label_in)
    //: label(label_in)
  {
    /*
    depth += 1;
    log(true);
    */
  }

  ~RAIILog() = default;
  /*
  {
    log(false);
    depth -= 1;
  }

  void log(bool inout) const {
    const auto pad = std::string(2 * depth, ' ');
    const auto symbol = (inout)? "> " : "< ";
    std::cout << pad << symbol << label << std::endl;
  }

  std::string label;
  */

  static int depth;
};

int RAIILog::depth = 0;

///
/// Convert between native identifiers / errors and OpenSSL ones
///

static std::string
openssl_error_string(const std::string& label, int error) {
  const auto err_string = std::string(ERR_error_string(error, nullptr));
  return label + ": " + err_string;
}

openssl_error::openssl_error(const std::string& label)
  : std::runtime_error(openssl_error_string(label, ERR_get_error()))
{}

static const EVP_MD*
openssl_digest_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_sha256();

    case CipherSuite::AES_GCM_256_SHA512:
      return EVP_sha512();

    default:
      throw unsupported_ciphersuite_error();
  }
}

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
      return EVP_aes_128_ctr();

    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_aes_128_gcm();

    case CipherSuite::AES_GCM_256_SHA512:
      return EVP_aes_256_gcm();

    default:
      throw unsupported_ciphersuite_error();
  }
}

static size_t
openssl_tag_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
      return 4;

    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
      return 8;

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512:
      return 16;

    default:
      throw unsupported_ciphersuite_error();
  }
}

///
/// Information about algorithms
///

size_t
cipher_digest_size(CipherSuite suite)
{
  return EVP_MD_size(openssl_digest_type(suite));
}

size_t
cipher_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_GCM_128_SHA256:
      return 16;

    case CipherSuite::AES_GCM_256_SHA512:
      return 32;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512:
      return 12;

    default:
      throw unsupported_ciphersuite_error();
  }
}

///
/// HMAC and HKDF
///

HMAC::HMAC(CipherSuite suite, input_bytes key)
  : ctx(HMAC_CTX_new(), HMAC_CTX_free)
{
  RAIILog log("HMAC::HMAC");
  auto type = openssl_digest_type(suite);
  auto key_size = static_cast<int>(key.size());
  if (1 != HMAC_Init_ex(ctx.get(), key.data(), key_size, type, nullptr)) {
    printf("%p %p %d %p %d\n", (void*)ctx.get(), (void*)key.data(), key_size, (void*)type, EVP_MD_type(type));
    throw openssl_error("HMAC init");
  }
}

void
HMAC::write(input_bytes data)
{
  RAIILog log("HMAC::write");
  if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
    throw openssl_error("HMAC update");
  }
}

input_bytes
HMAC::digest()
{
  RAIILog log("HMAC::digest");
  unsigned int size = 0;
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error("HMAC final");
  }

  return input_bytes(md.data(), size);
}

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm)
{
  auto hmac = HMAC(suite, salt);
  hmac.write(ikm);
  auto mac = hmac.digest();
  return bytes(mac.begin(), mac.end());
}

// For simplicity, we enforce that size <= Hash.length, so that
// HKDF-Expand(Secret, Label) reduces to:
//
//   HMAC(Secret, Label || 0x01)
bytes
hkdf_expand(CipherSuite suite,
            const bytes& secret,
            const bytes& info,
            size_t size)
{
  RAIILog log("hkdf_expand");
  // Ensure that we need only one hash invocation
  if (size > cipher_digest_size(suite)) {
    throw invalid_parameter_error("Size too big for hkdf_expand");
  }

  auto label = info;
  label.push_back(0x01);
  auto hmac = HMAC(suite, secret);
  hmac.write(label);
  auto mac = hmac.digest();
  return bytes(mac.begin(), mac.begin() + size);
}

///
/// AEAD Algorithms
///

static void
ctr_crypt(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  RAIILog log("ctr_crypt");
  if (out.size() != in.size()) {
    throw buffer_too_small_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error("CTR alloc");
  }

  static auto padded_nonce =
    std::array<uint8_t, 16>{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  std::copy(nonce.begin(), nonce.end(), padded_nonce.begin());

  auto cipher = openssl_cipher(suite);
  if (1 !=
      EVP_EncryptInit(ctx.get(), cipher, key.data(), padded_nonce.data())) {
    throw openssl_error("CTR init");
  }

  int outlen = 0;
  auto in_size_int = static_cast<int>(in.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), out.data(), &outlen, in.data(), in_size_int)) {
    throw openssl_error("CTR update");
  }

  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error("CTR final");
  }
}

static output_bytes
seal_ctr(CipherSuite suite,
         const bytes& key,
         const bytes& nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  RAIILog log("seal_ctr");
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Split the key into enc and auth subkeys
  auto key_span = input_bytes(key);
  auto enc_key_size = cipher_key_size(suite);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  ctr_crypt(suite, enc_key, nonce, inner_ct, pt);

  // Authenticate with truncated HMAC
  auto hmac = HMAC(suite, auth_key);
  hmac.write(aad);
  hmac.write(inner_ct);
  auto mac = hmac.digest();
  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac.begin(), mac.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
seal_aead(CipherSuite suite,
          const bytes& key,
          const bytes& nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  RAIILog log("seal_aead");
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error("AEAD seal alloc");
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error("AEAD seal init");
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad_size_int)) {
      throw openssl_error("AEAD seal update (1)");
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw openssl_error("AEAD seal update (2)");
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error("AEAD seal final");
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error("AEAD seal tag");
  }

  return ct.subspan(0, pt.size() + tag_size);
}

output_bytes
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  RAIILog log("seal");
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8: {
      return seal_ctr(suite, key, nonce, ct, aad, pt);
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return seal_aead(suite, key, nonce, ct, aad, pt);
    }
  }

  throw unsupported_ciphersuite_error();
}

static output_bytes
open_ctr(CipherSuite suite,
         const bytes& key,
         const bytes& nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  RAIILog log("open_ctr");
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Split the key into enc and auth subkeys
  auto key_span = input_bytes(key);
  auto enc_key_size = cipher_key_size(suite);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Authenticate with truncated HMAC
  auto hmac = HMAC(suite, auth_key);
  hmac.write(aad);
  hmac.write(inner_ct);
  auto mac = hmac.digest();
  if (CRYPTO_memcmp(mac.data(), tag.data(), tag.size()) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CM
  ctr_crypt(suite, enc_key, nonce, pt, ct.subspan(0, inner_ct_size));

  return pt.subspan(0, inner_ct_size);
}

static output_bytes
open_aead(CipherSuite suite,
          const bytes& key,
          const bytes& nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  RAIILog log("open_aead");
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error("AEAD open alloc");
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error("AEAD open init");
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error("AEAD open tag");
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad_size_int)) {
      throw openssl_error("AEAD open update");
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw openssl_error("AEAD open final");
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

output_bytes
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  RAIILog log("open");
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_CM_128_HMAC_SHA256_8: {
      return open_ctr(suite, key, nonce, pt, aad, ct);
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return open_aead(suite, key, nonce, pt, aad, ct);
    }
  }

  throw unsupported_ciphersuite_error();
}

} // namespace sframe
