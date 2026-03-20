# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/name_resolver'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'
require 'jwe/validator'
require 'jwe/header'

# A ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard.
module JWE
  class DecodeError < RuntimeError; end
  class NotImplementedError < RuntimeError; end
  class BadCEK < RuntimeError; end
  class InvalidData < RuntimeError; end

  class << self
    def encrypt(payload, key, alg: 'RSA-OAEP', enc: 'A128GCM', zip: nil, **more_headers)
      Validator.new.check_params(alg, enc, zip, key)
      payload = Zip.for(zip).new.compress(payload) if zip

      enc_cipher = Enc.for(enc)
      enc_cipher.cek = key if alg == 'dir'

      alg_cipher = Alg.for(alg).new(key)
      encrypted_cek = alg_cipher.encrypt(enc_cipher.cek)

      header = Header.new.generate_header(alg_cipher, enc_cipher, zip, more_headers)

      ciphertext = enc_cipher.encrypt(payload, Base64.jwe_encode(header))

      Serialization::Compact.encode(header, encrypted_cek, enc_cipher.iv, ciphertext, enc_cipher.tag)
    end

    def decrypt(payload, key)
      header, enc_key, iv, ciphertext, tag = Serialization::Compact.decode(payload)
      header = JSON.parse(header)
      alg, enc, zip = header.values_at('alg', 'enc', 'zip')

      Validator.new.check_params(alg, enc, zip, key)

      alg_cipher = Alg.for(alg).new(key)
      if alg_cipher.need_additional_header_parameters?
        alg_cipher.iv = Base64.jwe_decode(header['iv'])
        alg_cipher.tag = Base64.jwe_decode(header['tag'])
      end

      cek = alg_cipher.decrypt(enc_key)
      enc_cipher = Enc.for(enc, cek, iv, tag)

      plaintext = enc_cipher.decrypt(ciphertext, payload.split('.').first)

      return plaintext unless zip

      Zip.for(zip).new.decompress(plaintext)
    end

    # @deprecated Use Validator.new.check_params instead
    def check_params(header, key)
      warn '[DEPRECATION] `JWE.check_params` is deprecated. Use `JWE::Validator.new.check_params` instead.'
      check_alg(header[:alg] || header['alg'])
      check_enc(header[:enc] || header['enc'])
      check_zip(header[:zip] || header['zip'])
      check_key(key)
    end

    # @deprecated Use Validator.new.check_params instead
    def check_alg(alg)
      warn '[DEPRECATION] `JWE.check_alg` is deprecated. Please validate parameters manually.'
      raise ArgumentError.new("\"#{alg}\" is not a valid alg method") unless Validator::VALID_ALG.include?(alg)
    end

    # @deprecated Use Validator.new.check_params instead
    def check_enc(enc)
      warn '[DEPRECATION] `JWE.check_enc` is deprecated. Please validate parameters manually.'
      raise ArgumentError.new("\"#{enc}\" is not a valid enc method") unless Validator::VALID_ENC.include?(enc)
    end

    # @deprecated Use Validator.new.check_params instead
    def check_zip(zip)
      warn '[DEPRECATION] `JWE.check_zip` is deprecated. Please validate parameters manually.'
      raise ArgumentError.new("\"#{zip}\" is not a valid zip method") unless zip.nil? || zip == '' || Validator::VALID_ZIP.include?(zip)
    end

    # @deprecated Use Validator.new.check_params instead
    def check_key(key)
      warn '[DEPRECATION] `JWE.check_key` is deprecated. Please validate parameters manually.'
      raise ArgumentError.new('The key must not be nil or blank') if key.nil? || (key.is_a?(String) && key.strip == '')
    end

    # @deprecated Use NameResolver#param_to_class_name instead
    def param_to_class_name(param)
      warn '[DEPRECATION] `JWE.param_to_class_name` is deprecated. Use `JWE::NameResolver#param_to_class_name` instead.'
      klass = param.gsub(/[-+]/, '_').downcase.sub(/^[a-z\d]*/) { ::Regexp.last_match(0).capitalize }
      klass.gsub(/_([a-z\d]*)/i) { Regexp.last_match(1).capitalize }
    end

    # @deprecated Internal method, do not use
    def apply_zip(header, data, direction)
      warn '[DEPRECATION] `JWE.apply_zip` is deprecated. This is an internal method and should not be used externally.'
      zip = header[:zip] || header['zip']
      if zip
        Zip.for(zip).new.send(direction, data)
      else
        data
      end
    end

    # @deprecated Use Header.new.generate_header instead
    def generate_header(alg, enc, more)
      warn '[DEPRECATION] `JWE.generate_header` is deprecated. This is an internal method and should not be used externally.'
      header = { alg: alg, enc: enc }.merge(more)
      header.delete(:zip) if header[:zip] == ''
      header
    end

    # @deprecated Use Serialization::Compact.encode instead
    def generate_serialization(hdr, cek, content, cipher)
      warn '[DEPRECATION] `JWE.generate_serialization` is deprecated. Use `JWE::Serialization::Compact.encode` instead.'
      Serialization::Compact.encode(hdr, cek, cipher.iv, content, cipher.tag)
    end
  end
end
