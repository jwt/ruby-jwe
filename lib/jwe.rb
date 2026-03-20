# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'

# A ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard.
module JWE
  class DecodeError < RuntimeError; end
  class NotImplementedError < RuntimeError; end
  class BadCEK < RuntimeError; end
  class InvalidData < RuntimeError; end

  VALID_ALG = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A192KW', 'A256KW', 'dir', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'].freeze
  VALID_ENC = %w[A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM].freeze
  VALID_ZIP = ['DEF'].freeze

  REGISTERED_HEADERS = %w[
    alg enc zip jku jwk kid x5u x5c x5t x5t#S256 typ cty crit
  ].freeze

  class << self
    attr_accessor :supported_critical_headers

    def encrypt(payload, key, alg: 'RSA-OAEP', enc: 'A128GCM', **more_headers)
      header = generate_header(alg, enc, more_headers)
      check_params(header, key)

      payload = apply_zip(header, payload, :compress)

      cipher = Enc.for(enc)
      cipher.cek = key if alg == 'dir'

      json_hdr = header.to_json
      ciphertext = cipher.encrypt(payload, Base64.jwe_encode(json_hdr))

      generate_serialization(json_hdr, Alg.encrypt_cek(alg, key, cipher.cek), ciphertext, cipher)
    end

    def decrypt(payload, key)
      header, enc_key, iv, ciphertext, tag = Serialization::Compact.decode(payload)
      header = JSON.parse(header)
      check_params(header, key)

      cek = Alg.decrypt_cek(header['alg'], key, enc_key)
      cipher = Enc.for(header['enc'], cek, iv, tag)

      plaintext = cipher.decrypt(ciphertext, payload.split('.').first)

      apply_zip(header, plaintext, :decompress)
    end

    def check_params(header, key)
      check_alg(header[:alg] || header['alg'])
      check_enc(header[:enc] || header['enc'])
      check_zip(header[:zip] || header['zip'])
      check_crit(header)
      check_key(key)
    end

    def check_alg(alg)
      raise ArgumentError.new("\"#{alg}\" is not a valid alg method") unless VALID_ALG.include?(alg)
    end

    def check_enc(enc)
      raise ArgumentError.new("\"#{enc}\" is not a valid enc method") unless VALID_ENC.include?(enc)
    end

    def check_zip(zip)
      raise ArgumentError.new("\"#{zip}\" is not a valid zip method") unless zip.nil? || zip == '' || VALID_ZIP.include?(zip)
    end

    def check_key(key)
      raise ArgumentError.new('The key must not be nil or blank') if key.nil? || (key.is_a?(String) && key.strip == '')
    end

    def check_crit(header)
      crit = header[:crit] || header['crit']
      return if crit.nil?

      raise ArgumentError, '"crit" header must be a non-empty array' unless crit.is_a?(Array) && !crit.empty?

      crit.each { |param| validate_critical_param(header, param) }
    end

    def validate_critical_param(header, param)
      raise ArgumentError, "\"#{param}\" is a registered header and cannot be in \"crit\"" if REGISTERED_HEADERS.include?(param)
      raise ArgumentError, "\"#{param}\" is in \"crit\" but not present in header" unless header.key?(param) || header.key?(param.to_sym)
      raise JWE::InvalidData, "Unsupported critical header: \"#{param}\"" unless supported_critical_headers.include?(param)
    end

    def param_to_class_name(param)
      klass = param.gsub(/[-+]/, '_').downcase.sub(/^[a-z\d]*/) { ::Regexp.last_match(0).capitalize }
      klass.gsub(/_([a-z\d]*)/i) { Regexp.last_match(1).capitalize }
    end

    def apply_zip(header, data, direction)
      zip = header[:zip] || header['zip']
      if zip
        Zip.for(zip).new.send(direction, data)
      else
        data
      end
    end

    def generate_header(alg, enc, more)
      header = { alg: alg, enc: enc }.merge(more)
      header.delete(:zip) if header[:zip] == ''
      header
    end

    def generate_serialization(hdr, cek, content, cipher)
      Serialization::Compact.encode(hdr, cek, cipher.iv, content, cipher.tag)
    end
  end

  self.supported_critical_headers = []
end
