#include "crypto.h"
#include "header.h"

#include <openssl/err.h>
#include <openssl/evp.h>

namespace sframe {

///
/// Convert between native identifiers / errors and OpenSSL ones
///

openssl_error::openssl_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{
}

static const EVP_MD*
openssl_digest_type(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
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
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return EVP_aes_128_ctr();

    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_aes_128_gcm();

    case CipherSuite::AES_GCM_256_SHA512:
      return EVP_aes_256_gcm();

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
overhead(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
      return 10;

    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
      return 8;

    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return 4;

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
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return 48;

    case CipherSuite::AES_GCM_256_SHA512:
      return 32;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_enc_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return 16;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
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
  const auto type = openssl_digest_type(suite);

  // Some FIPS-enabled libraries are overly conservative in their interpretation
  // of NIST SP 800-131A, which requires HMAC keys to be at least 112 bits long.
  // That document does not impose that requirement on HKDF, so we disable FIPS
  // enforcement for purposes of HKDF.
  //
  // https://doi.org/10.6028/NIST.SP.800-131Ar2
  static const auto fips_min_hmac_key_len = 14;
  auto key_size = static_cast<int>(key.size());
  if (FIPS_mode() != 0 && key_size < fips_min_hmac_key_len) {
    HMAC_CTX_set_flags(ctx.get(), EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
  }

  // Guard against sending nullptr to HMAC_Init_ex
  const auto* key_data = key.data();
  const auto non_null_zero_length_key = uint8_t(0);
  if (key_data == nullptr) {
    key_data = &non_null_zero_length_key;
  }

  if (1 != HMAC_Init_ex(ctx.get(), key_data, key_size, type, nullptr)) {
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

HMAC::Output
HMAC::digest()
{
  unsigned int size = int(0);
  auto md = Output{};
  if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
    throw openssl_error();
  }

  md.resize(static_cast<size_t>(size));
  return md;
}

HMAC::Output
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  auto h = HMAC(suite, salt);
  h.write(ikm);
  return h.digest();
}

owned_bytes<max_hkdf_extract_size>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  // Ensure that we need only one hash invocation
  if (size > max_hkdf_extract_size) {
    throw invalid_parameter_error("Size too big for hkdf_expand");
  }

  auto out = owned_bytes<max_hkdf_extract_size>(0);

  auto block = HMAC::Output(0);
  const auto block_size = cipher_digest_size(suite);
  auto counter = uint8_t(0x01);
  while (out.size() < size) {
  // for (auto start = size_t(0); start < out.size(); start += block_size) {
    auto h = HMAC(suite, prk);
    h.write(block);
    h.write(info);
    h.write(owned_bytes<1>{ counter });
    block = h.digest();

    const auto remaining = size - out.size();
    const auto to_write = (remaining < block_size) ? remaining : block_size;
    out.append(input_bytes(block).first(to_write));

    counter += 1;
  }

  return out;
}

///
/// AEAD Algorithms
///

static HMAC::Output
compute_tag(CipherSuite suite,
            input_bytes auth_key,
            input_bytes nonce,
            input_bytes aad,
            input_bytes ct,
            size_t tag_size)
{
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  auto h = HMAC(suite, auth_key);
  h.write(len_block);
  h.write(nonce);
  h.write(aad);
  h.write(ct);

  auto tag = h.digest();
  tag.resize(tag_size);
  return tag;
}

static void
ctr_crypt(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  if (out.size() != in.size()) {
    throw buffer_too_small_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

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
         input_bytes key,
         input_bytes nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  auto tag_size = overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Split the key into enc and auth subkeys
  auto enc_key_size = cipher_enc_key_size(suite);
  auto enc_key = key.first(enc_key_size);
  auto auth_key = key.subspan(enc_key_size);

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  ctr_crypt(suite, enc_key, nonce, inner_ct, pt);

  // Authenticate with truncated HMAC
  auto mac = compute_tag(suite, auth_key, nonce, aad, inner_ct, tag_size);
  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac.begin(), mac.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
seal_aead(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  auto tag_size = overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
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
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

output_bytes
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32: {
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
         input_bytes key,
         input_bytes nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  auto tag_size = overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Split the key into enc and auth subkeys
  auto enc_key_size = cipher_enc_key_size(suite);
  auto enc_key = key.first(enc_key_size);
  auto auth_key = key.subspan(enc_key_size);

  // Authenticate with truncated HMAC
  auto mac = compute_tag(suite, auth_key, nonce, aad, inner_ct, tag_size);
  if (CRYPTO_memcmp(mac.data(), tag.data(), tag.size()) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CTR
  const auto pt_out = pt.first(inner_ct_size);
  ctr_crypt(suite, enc_key, nonce, pt_out, ct.first(inner_ct_size));

  return pt_out;
}

static output_bytes
open_aead(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  auto tag_size = overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
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
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
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
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

output_bytes
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32: {
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
