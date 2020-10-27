#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>

namespace sframe {

///
/// Convert between native identifiers / errors and OpenSSL ones
///

static std::runtime_error
openssl_error()
{
  auto code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
}

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
      throw std::runtime_error("Unsupported ciphersuite");
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
      throw std::runtime_error("Unsupported ciphersuite");
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
      throw std::runtime_error("Unsupported ciphersuite");
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
      throw std::runtime_error("Unsupported ciphersuite");
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
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

///
/// HMAC and HKDF
///

HMAC::HMAC(CipherSuite suite, input_bytes key)
  : ctx(HMAC_CTX_new(), HMAC_CTX_free)
{
  auto type = openssl_digest_type(suite);
  if (1 != HMAC_Init_ex(ctx.get(), key.data(), key.size(), type, nullptr)) {
    throw openssl_error();
  }
}

void
HMAC::write(input_bytes data)
{
  if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
    throw openssl_error();
  }
}

input_bytes
HMAC::digest()
{
  unsigned int size = 0;
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error();
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
  // Ensure that we need only one hash invocation
  if (size > cipher_digest_size(suite)) {
    throw std::runtime_error("Size too big for hkdf_expand");
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
  if (out.size() != in.size()) {
    throw std::runtime_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  static auto padded_nonce =
    std::array<uint8_t, 16>{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  std::copy(nonce.begin(), nonce.end(), padded_nonce.begin());

  auto cipher = openssl_cipher(suite);
  if (1 !=
      EVP_EncryptInit(ctx.get(), cipher, key.data(), padded_nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto in_size_int = static_cast<int>(in.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), out.data(), &outlen, in.data(), in_size_int)) {
    throw openssl_error();
  }

  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
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
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw std::runtime_error("Ciphertext buffer too small");
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
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw std::runtime_error("Ciphertext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag_ptr)) {
    throw openssl_error();
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

  throw std::runtime_error("Unknown algorithm");
}

static output_bytes
open_ctr(CipherSuite suite,
         const bytes& key,
         const bytes& nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < tag_size) {
    throw std::runtime_error("Ciphertext buffer too small");
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
    throw std::runtime_error("AEAD authentication failure");
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
  auto tag_size = openssl_tag_size(suite);
  if (ct.size() < tag_size) {
    throw std::runtime_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw std::runtime_error("Plaintext buffer too small");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag_ptr)) {
    throw openssl_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw std::runtime_error("AEAD authentication failure");
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

  throw std::runtime_error("Unknown algorithm");
}

} // namespace sframe
