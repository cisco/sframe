#include <sframe/sframe.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <array>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <tuple>

namespace sframe {

std::ostream&
operator<<(std::ostream& str, const input_bytes data)
{
  str.flags(std::ios::hex);
  for (const auto& byte : data) {
    str << std::setw(2) << std::setfill('0') << int(byte);
  }
  return str;
}

static auto evp_cipher_ctx_free = [](EVP_CIPHER_CTX* ptr) {
  EVP_CIPHER_CTX_free(ptr);
};

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(evp_cipher_ctx_free)>;

static std::runtime_error
openssl_error()
{
  auto code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
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
openssl_key_size(CipherSuite suite)
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

static size_t
openssl_nonce_size(CipherSuite suite)
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

static size_t
openssl_digest_size(CipherSuite suite)
{
  return EVP_MD_size(openssl_digest_type(suite));
}

static input_bytes
hmac(CipherSuite suite, input_bytes key, input_bytes data)
{
  static auto md = std::array<uint8_t, EVP_MAX_MD_SIZE>();

  unsigned int size = 0;
  auto type = openssl_digest_type(suite);
  if (nullptr == HMAC(type,
                      key.data(),
                      key.size(),
                      data.data(),
                      data.size(),
                      md.data(),
                      &size)) {
    throw std::runtime_error("HMAC failure");
  }

  return input_bytes(md.data(), size);
}

static bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm)
{
  auto mac = hmac(suite, salt, ikm);
  return bytes(mac.begin(), mac.end());
}

// For simplicity, we enforce that size <= Hash.length, so that
// HKDF-Expand(Secret, Label) reduces to:
//
//   HMAC(Secret, Label || 0x01)
static bytes
hkdf_expand(CipherSuite suite,
            const bytes& secret,
            const bytes& info,
            size_t size)
{
  // Ensure that we need only one hash invocation
  if (size > openssl_digest_size(suite)) {
    throw std::runtime_error("Size too big for hkdf_expand");
  }

  auto label = info;
  label.push_back(0x01);
  auto mac = hmac(suite, secret, label);
  return bytes(mac.begin(), mac.begin() + size);
}

void
ctr_crypt(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  if (out.size() != in.size()) {
    std::cout << out.size() << " <> " << in.size() << std::endl;
    throw std::runtime_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), evp_cipher_ctx_free);
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
  auto enc_key_size = openssl_key_size(suite);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  ctr_crypt(suite, enc_key, nonce, inner_ct, pt);

  // Authenticate with truncated HMAC
  auto mac_input = bytes(aad.begin(), aad.end());
  mac_input.insert(mac_input.end(), inner_ct.begin(), inner_ct.end());
  auto mac = hmac(suite, auth_key, mac_input);

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

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), evp_cipher_ctx_free);
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
  if (1 !=
      EVP_EncryptUpdate(
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
  if (1 !=
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag_ptr)) {
    throw openssl_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
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
  auto enc_key_size = openssl_key_size(suite);
  auto enc_key = key_span.subspan(0, enc_key_size);
  auto auth_key = key_span.subspan(enc_key_size);

  // Authenticate with truncated HMAC
  auto mac_input = bytes(aad.begin(), aad.end());
  mac_input.insert(mac_input.end(), inner_ct.begin(), inner_ct.end());
  auto mac = hmac(suite, auth_key, mac_input);
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

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), evp_cipher_ctx_free);
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

static output_bytes
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

Context::Context(CipherSuite suite_in)
  : suite(suite_in)
{}

static const bytes sframe_label{
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30 // "SFrame10"
};
static const bytes sframe_key_label{ 0x6b, 0x65, 0x79 };        // "key"
static const bytes sframe_salt_label{ 0x73, 0x61, 0x6c, 0x74 }; // "salt"

static const bytes sframe_ctr_label{
  // "SFrame10 AES CM AEAD"
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30, 0x20, 0x41,
  0x45, 0x53, 0x20, 0x43, 0x4d, 0x20, 0x41, 0x45, 0x41, 0x44,
};
static const bytes sframe_enc_label{ 0x65, 0x6e, 0x63 };        // "enc"
static const bytes sframe_auth_label{ 0x61, 0x75, 0x74, 0x68 }; // "auth"

void
Context::add_key(KeyID key_id, const bytes& base_key)
{
  auto key_size = openssl_key_size(suite);
  auto nonce_size = openssl_nonce_size(suite);
  auto hash_size = openssl_digest_size(suite);

  auto secret = hkdf_extract(suite, sframe_label, base_key);
  auto key = hkdf_expand(suite, secret, sframe_key_label, key_size);
  auto salt = hkdf_expand(suite, secret, sframe_salt_label, nonce_size);

  // If using CTR+HMAC, set key = enc_key || auth_key
  if (suite == CipherSuite::AES_CM_128_HMAC_SHA256_4 ||
      suite == CipherSuite::AES_CM_128_HMAC_SHA256_8) {
    secret = hkdf_extract(suite, sframe_ctr_label, key);

    auto main_key = key;
    auto enc_key = hkdf_expand(suite, secret, sframe_enc_label, key_size);
    auto auth_key = hkdf_expand(suite, secret, sframe_auth_label, hash_size);

    key = enc_key;
    key.insert(key.end(), auth_key.begin(), auth_key.end());
  }

  state.insert_or_assign(key_id,
                         KeyState{ std::move(key), std::move(salt), 0 });
}

static size_t
encode_uint(uint64_t val, output_bytes start)
{
  size_t size = 1;
  while (val >> (8 * size) > 0) {
    size += 1;
  }

  for (size_t i = 0; i < size; i++) {
    start[size - i - 1] = uint8_t(val >> (8 * i));
  }

  return size;
}

static uint64_t
decode_uint(input_bytes data)
{
  uint64_t val = 0;
  for (size_t i = 0; i < data.size(); i++) {
    val = (val << 8) + static_cast<uint64_t>(data[i]);
  }
  return val;
}

static bytes
form_nonce(CipherSuite suite, Counter ctr, const bytes& salt)
{
  auto nonce_size = openssl_nonce_size(suite);
  auto nonce = bytes(nonce_size);
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce_size - i - 1] = uint8_t(ctr >> (8 * i));
  }

  for (size_t i = 0; i < nonce.size(); i++) {
    nonce[i] ^= salt[i];
  }

  return nonce;
}

static constexpr size_t min_header_size = 1;
static constexpr size_t max_header_size = 1 + 8 + 8;

static size_t
encode_header(KeyID kid, Counter ctr, output_bytes data)
{
  size_t kid_size = 0;
  if (kid > 0x07) {
    kid_size = encode_uint(kid, data.subspan(1));
  }

  size_t ctr_size = encode_uint(ctr, data.subspan(1 + kid_size));
  if ((ctr_size > 0x07) || (kid_size > 0x07)) {
    throw std::runtime_error("Header overflow");
  }

  data[0] = uint8_t(ctr_size << 4);
  if (kid <= 0x07) {
    data[0] |= kid;
  } else {
    data[0] |= 0x08 | kid_size;
  }

  return 1 + kid_size + ctr_size;
}

static std::tuple<KeyID, Counter, input_bytes>
decode_header(input_bytes data)
{
  if (data.size() < min_header_size) {
    throw std::runtime_error("Ciphertext too small to decode header");
  }

  auto cfg = data[0];
  auto ctr_size = size_t((cfg >> 4) & 0x07);
  auto kid_long = (cfg & 0x08) > 0;
  auto kid_size = size_t(cfg & 0x07);

  auto kid = KeyID(kid_size);
  if (kid_long) {
    if (data.size() < 1 + kid_size) {
      throw std::runtime_error("Ciphertext too small to decode KID");
    }

    kid = KeyID(decode_uint(data.subspan(1, kid_size)));
  } else {
    kid_size = 0;
  }

  if (data.size() < 1 + kid_size + ctr_size) {
    throw std::runtime_error("Ciphertext too small to decode CTR");
  }
  auto ctr = Counter(decode_uint(data.subspan(1 + kid_size, ctr_size)));

  return std::make_tuple(kid, ctr, data.subspan(0, 1 + kid_size + ctr_size));
}

output_bytes
Context::protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  auto it = state.find(key_id);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  auto& st = it->second;
  const auto ctr = st.counter;
  st.counter += 1;

  if (ciphertext.size() < max_header_size) {
    throw std::runtime_error("Ciphertext to small to encod header");
  }

  auto hdr_size = encode_header(key_id, ctr, ciphertext);
  auto header = ciphertext.subspan(0, hdr_size);
  auto inner_ciphertext = ciphertext.subspan(hdr_size);

  const auto nonce = form_nonce(suite, ctr, st.salt);
  auto final_ciphertext = seal(suite, st.key, nonce, inner_ciphertext, header, plaintext);
  return ciphertext.subspan(0, hdr_size + final_ciphertext.size());
}

output_bytes
Context::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  auto [kid, ctr, header] = decode_header(ciphertext);
  auto inner_ciphertext = ciphertext.subspan(header.size());

  auto it = state.find(kid);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  const auto& st = it->second;
  const auto nonce = form_nonce(suite, ctr, st.salt);
  return open(suite, st.key, nonce, plaintext, header, inner_ciphertext);
}

} // namespace sframe
