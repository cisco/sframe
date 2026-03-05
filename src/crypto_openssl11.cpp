#if defined(OPENSSL_1_1)

#include "crypto.h"
#include "header.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace SFRAME_NAMESPACE {

///
/// Scoped pointers for OpenSSL objects
///

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using scoped_hmac_ctx = std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)>;

///
/// Convert between native identifiers / errors and OpenSSL ones
///

crypto_error::crypto_error()
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

static bool
is_ctr_hmac_suite(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return true;
    default:
      return false;
  }
}

///
/// CipherHandle and HmacHandle definitions
///

struct CipherHandle
{
  scoped_evp_ctx ctx;
  CipherHandle()
    : ctx(nullptr, EVP_CIPHER_CTX_free)
  {
  }
};

struct HmacHandle
{
  scoped_hmac_ctx ctx;
  HmacHandle()
    : ctx(nullptr, HMAC_CTX_free)
  {
  }
};

void
CipherState::Deleter::operator()(CipherHandle* h) const
{
  delete h;
}

void
CipherState::Deleter::operator()(HmacHandle* h) const
{
  delete h;
}

CipherState::CipherState(CipherHandle* cipher,
                         HmacHandle* hmac,
                         CipherSuite suite_in)
  : cipher_handle(cipher)
  , hmac_handle(hmac)
  , suite(suite_in)
{
}

CipherState
CipherState::create_seal(CipherSuite suite, input_bytes key)
{
  auto cipher_h = std::make_unique<CipherHandle>();
  cipher_h->ctx.reset(EVP_CIPHER_CTX_new());
  if (cipher_h->ctx == nullptr) {
    throw crypto_error();
  }

  auto cipher = openssl_cipher(suite);
  std::unique_ptr<HmacHandle> hmac_h;

  if (is_ctr_hmac_suite(suite)) {
    // CTR+HMAC: key is split into enc_key and auth_key
    auto enc_key_size = cipher_enc_key_size(suite);
    auto enc_key = key.first(enc_key_size);
    auto auth_key = key.subspan(enc_key_size);

    // Initialize AES-CTR context (always encrypt for CTR mode)
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, enc_key.data(), nullptr)) {
      throw crypto_error();
    }

    // Initialize HMAC
    hmac_h = std::make_unique<HmacHandle>();
    hmac_h->ctx.reset(HMAC_CTX_new());
    if (hmac_h->ctx == nullptr) {
      throw crypto_error();
    }

    const auto* md = openssl_digest_type(suite);
    auto key_size = static_cast<int>(auth_key.size());
    if (1 != HMAC_Init_ex(
               hmac_h->ctx.get(), auth_key.data(), key_size, md, nullptr)) {
      throw crypto_error();
    }
  } else {
    // GCM: use full key
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, key.data(), nullptr)) {
      throw crypto_error();
    }
  }

  return CipherState(cipher_h.release(), hmac_h.release(), suite);
}

CipherState
CipherState::create_open(CipherSuite suite, input_bytes key)
{
  auto cipher_h = std::make_unique<CipherHandle>();
  cipher_h->ctx.reset(EVP_CIPHER_CTX_new());
  if (cipher_h->ctx == nullptr) {
    throw crypto_error();
  }

  auto cipher = openssl_cipher(suite);
  std::unique_ptr<HmacHandle> hmac_h;

  if (is_ctr_hmac_suite(suite)) {
    // CTR+HMAC: key is split into enc_key and auth_key
    auto enc_key_size = cipher_enc_key_size(suite);
    auto enc_key = key.first(enc_key_size);
    auto auth_key = key.subspan(enc_key_size);

    // Initialize AES-CTR context (always encrypt for CTR mode - CTR is
    // symmetric)
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, enc_key.data(), nullptr)) {
      throw crypto_error();
    }

    // Initialize HMAC
    hmac_h = std::make_unique<HmacHandle>();
    hmac_h->ctx.reset(HMAC_CTX_new());
    if (hmac_h->ctx == nullptr) {
      throw crypto_error();
    }

    const auto* md = openssl_digest_type(suite);
    auto key_size = static_cast<int>(auth_key.size());
    if (1 != HMAC_Init_ex(
               hmac_h->ctx.get(), auth_key.data(), key_size, md, nullptr)) {
      throw crypto_error();
    }
  } else {
    // GCM: use full key
    if (1 != EVP_DecryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, key.data(), nullptr)) {
      throw crypto_error();
    }
  }

  return CipherState(cipher_h.release(), hmac_h.release(), suite);
}

///
/// AEAD Algorithms - CTR+HMAC
///

static output_bytes
seal_ctr(EVP_CIPHER_CTX* ctx,
         HMAC_CTX* hmac,
         CipherSuite suite,
         input_bytes nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Pad nonce to 16 bytes for AES-CTR
  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

  // Reset AES-CTR context with new nonce (key is preserved)
  if (1 !=
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, padded_nonce.data())) {
    throw crypto_error();
  }

  // Encrypt with AES-CTR
  auto inner_ct = ct.subspan(0, pt.size());
  int outlen = 0;
  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx, inner_ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  // Compute HMAC tag
  // Reset HMAC context (key is preserved from init)
  if (1 != HMAC_Init_ex(hmac, nullptr, 0, nullptr, nullptr)) {
    throw crypto_error();
  }

  // Build length block
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(inner_ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  if (1 != HMAC_Update(hmac, len_block.data(), len_block.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, nonce.data(), nonce.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, aad.data(), aad.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, inner_ct.data(), inner_ct.size())) {
    throw crypto_error();
  }

  auto mac_buf = owned_bytes<64>();
  unsigned int mac_size = mac_buf.size();
  if (1 != HMAC_Final(hmac, mac_buf.data(), &mac_size)) {
    throw crypto_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac_buf.begin(), mac_buf.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
open_ctr(EVP_CIPHER_CTX* ctx,
         HMAC_CTX* hmac,
         CipherSuite suite,
         input_bytes nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
  }

  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Verify HMAC tag
  // Reset HMAC context (key is preserved from init)
  if (1 != HMAC_Init_ex(hmac, nullptr, 0, nullptr, nullptr)) {
    throw crypto_error();
  }

  // Build length block
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(inner_ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  if (1 != HMAC_Update(hmac, len_block.data(), len_block.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, nonce.data(), nonce.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, aad.data(), aad.size())) {
    throw crypto_error();
  }
  if (1 != HMAC_Update(hmac, inner_ct.data(), inner_ct.size())) {
    throw crypto_error();
  }

  auto mac_buf = owned_bytes<64>();
  unsigned int mac_size = mac_buf.size();
  if (1 != HMAC_Final(hmac, mac_buf.data(), &mac_size)) {
    throw crypto_error();
  }

  if (CRYPTO_memcmp(mac_buf.data(), tag.data(), tag_size) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CTR
  // Pad nonce to 16 bytes for AES-CTR
  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

  // Reset AES-CTR context with new nonce (key is preserved)
  if (1 !=
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, padded_nonce.data())) {
    throw crypto_error();
  }

  int outlen = 0;
  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_EncryptUpdate(
             ctx, pt.data(), &outlen, inner_ct.data(), inner_ct_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  return pt.subspan(0, inner_ct_size);
}

///
/// AEAD Algorithms - GCM
///

static output_bytes
seal_aead(EVP_CIPHER_CTX* ctx,
          CipherSuite suite,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Reset context and set new nonce (key is preserved)
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data())) {
    throw crypto_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 !=
        EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), aad_size_int)) {
      throw crypto_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(ctx, ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx, EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw crypto_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
open_aead(EVP_CIPHER_CTX* ctx,
          CipherSuite suite,
          input_bytes nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
  }

  // Reset context and set new nonce (key is preserved)
  if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data())) {
    throw crypto_error();
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx, EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    throw crypto_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 !=
        EVP_DecryptUpdate(ctx, nullptr, &out_size, aad.data(), aad_size_int)) {
      throw crypto_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx, pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_DecryptFinal(ctx, nullptr, &out_size)) {
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

///
/// CipherState seal/open methods
///

output_bytes
CipherState::seal(input_bytes nonce,
                  output_bytes ct,
                  input_bytes aad,
                  input_bytes pt)
{
  if (is_ctr_hmac_suite(suite)) {
    return seal_ctr(cipher_handle->ctx.get(),
                    hmac_handle->ctx.get(),
                    suite,
                    nonce,
                    ct,
                    aad,
                    pt);
  }
  return seal_aead(cipher_handle->ctx.get(), suite, nonce, ct, aad, pt);
}

output_bytes
CipherState::open(input_bytes nonce,
                  output_bytes pt,
                  input_bytes aad,
                  input_bytes ct)
{
  if (is_ctr_hmac_suite(suite)) {
    return open_ctr(cipher_handle->ctx.get(),
                    hmac_handle->ctx.get(),
                    suite,
                    nonce,
                    pt,
                    aad,
                    ct);
  }
  return open_aead(cipher_handle->ctx.get(), suite, nonce, pt, aad, ct);
}

///
/// Stateless seal/open (used by test vectors)
///

output_bytes
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  auto state = CipherState::create_seal(suite, key);
  return state.seal(nonce, ct, aad, pt);
}

output_bytes
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  auto state = CipherState::create_open(suite, key);
  return state.open(nonce, pt, aad, ct);
}

///
/// HMAC wrapper class for HKDF
///

struct HMAC
{
private:
  scoped_hmac_ctx ctx;

public:
  HMAC(CipherSuite suite, input_bytes key)
    : ctx(HMAC_CTX_new(), HMAC_CTX_free)
  {
    const auto type = openssl_digest_type(suite);

    // Some FIPS-enabled libraries are overly conservative in their
    // interpretation of NIST SP 800-131A, which requires HMAC keys to be at
    // least 112 bits long. That document does not impose that requirement on
    // HKDF, so we disable FIPS enforcement for purposes of HKDF.
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
      throw crypto_error();
    }
  }

  void write(input_bytes data)
  {
    if (1 != HMAC_Update(ctx.get(), data.data(), data.size())) {
      throw crypto_error();
    }
  }

  output_bytes digest(output_bytes md)
  {
    unsigned int size = md.size();
    if (1 != HMAC_Final(ctx.get(), md.data(), &size)) {
      throw crypto_error();
    }

    return md.first(size);
  }
};

///
/// HKDF
///

owned_bytes<max_hkdf_expand_size>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  auto h = HMAC(suite, salt);
  h.write(ikm);

  auto out = owned_bytes<max_hkdf_expand_size>();
  const auto md = h.digest(out);
  out.resize(md.size());
  return out;
}

owned_bytes<max_hkdf_extract_size>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  // Ensure that we need only one hash invocation
  if (size > max_hkdf_extract_size) {
    throw invalid_parameter_error("Size too big for hkdf_expand");
  }

  auto out = owned_bytes<max_hkdf_extract_size>(0);

  auto block = owned_bytes<max_hkdf_extract_size>(0);
  const auto block_size = cipher_digest_size(suite);
  auto counter = owned_bytes<1>();
  counter[0] = 0x01;
  while (out.size() < size) {
    auto h = HMAC(suite, prk);
    h.write(block);
    h.write(info);
    h.write(counter);

    block.resize(block_size);
    h.digest(block);

    const auto remaining = size - out.size();
    const auto to_write = (remaining < block_size) ? remaining : block_size;
    out.append(input_bytes(block).first(to_write));

    counter[0] += 1;
  }

  return out;
}

} // namespace SFRAME_NAMESPACE

#endif // defined(OPENSSL_1_1)
