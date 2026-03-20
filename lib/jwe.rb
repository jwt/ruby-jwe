# frozen_string_literal: true

require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/serialization/json'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'
require 'jwe/recipient'
require 'jwe/decryption_result'

# A ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard.
module JWE # rubocop:disable Metrics/ModuleLength
  class DecodeError < RuntimeError; end
  class NotImplementedError < RuntimeError; end
  class BadCEK < RuntimeError; end
  class InvalidData < RuntimeError; end

  VALID_ALG = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A192KW', 'A256KW', 'dir', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'].freeze
  VALID_ENC = %w[A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM].freeze
  VALID_ZIP = ['DEF'].freeze

  class << self # rubocop:disable Metrics/ClassLength
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

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Metrics/ParameterLists
    def encrypt_json(payload, recipients, protected_header: {}, unprotected_header: nil, aad: nil, format: :general)
      raise ArgumentError, 'At least one recipient is required' if recipients.empty?
      raise ArgumentError, 'Flattened serialization supports only one recipient' if format == :flattened && recipients.length > 1

      enc = protected_header[:enc] || protected_header['enc']
      raise ArgumentError, 'enc is required in protected_header' unless enc

      check_enc(enc)

      cipher = Enc.for(enc)
      cek = cipher.cek

      recipient_data = recipients.map do |recipient|
        jose_header = build_jose_header(protected_header, unprotected_header, recipient.header)
        alg = jose_header['alg'] || jose_header[:alg]
        raise ArgumentError, 'alg is required for each recipient' unless alg

        check_alg(alg)
        check_key(recipient.key)

        encrypted_key = Alg.encrypt_cek(alg, recipient.key, cek)
        { header: recipient.header, encrypted_key: encrypted_key }
      end

      payload = apply_zip(protected_header, payload, :compress)

      protected_header_json = protected_header.transform_keys(&:to_s).to_json
      encoded_protected = Base64.jwe_encode(protected_header_json)

      aad_for_encryption = if aad
                             "#{encoded_protected}.#{Base64.jwe_encode(aad)}"
                           else
                             encoded_protected
                           end

      ciphertext = cipher.encrypt(payload, aad_for_encryption)

      if format == :flattened
        Serialization::Json::Flattened.encode(
          protected_header: encoded_protected,
          unprotected_header: unprotected_header,
          header: recipient_data[0][:header],
          encrypted_key: recipient_data[0][:encrypted_key],
          iv: cipher.iv,
          ciphertext: ciphertext,
          tag: cipher.tag,
          aad: aad
        )
      else
        Serialization::Json::General.encode(
          protected_header: encoded_protected,
          unprotected_header: unprotected_header,
          recipients: recipient_data,
          iv: cipher.iv,
          ciphertext: ciphertext,
          tag: cipher.tag,
          aad: aad
        )
      end
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Metrics/ParameterLists

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
    def decrypt_json(payload, keys)
      data = JSON.parse(payload)

      decoded = if data['recipients']
                  Serialization::Json::General.decode(data)
                else
                  Serialization::Json::Flattened.decode(data)
                end

      protected_header = if decoded[:protected_header]
                           JSON.parse(Base64.jwe_decode(decoded[:protected_header]))
                         else
                           {}
                         end
      unprotected_header = decoded[:unprotected_header] || {}

      key_map = normalize_keys(keys)

      successful_recipients = []
      failed_recipients = []
      plaintext = nil

      decoded[:recipients].each_with_index do |recipient, index|
        recipient_header = recipient[:header] || {}
        jose_header = protected_header.merge(unprotected_header).merge(recipient_header)

        validate_header_no_duplicates!(protected_header, unprotected_header, recipient_header)

        alg = jose_header['alg']
        enc = jose_header['enc']

        raise DecodeError, 'Missing alg in JOSE header' unless alg
        raise DecodeError, 'Missing enc in JOSE header' unless enc

        check_alg(alg)
        check_enc(enc)

        key = select_key(key_map, jose_header)
        next unless key

        begin
          cek = Alg.decrypt_cek(alg, key, recipient[:encrypted_key])

          aad_for_decryption = if decoded[:aad]
                                 "#{decoded[:protected_header]}.#{data['aad']}"
                               else
                                 decoded[:protected_header] || ''
                               end

          cipher = Enc.for(enc, cek, decoded[:iv], decoded[:tag])
          decrypted = cipher.decrypt(decoded[:ciphertext], aad_for_decryption)

          plaintext = apply_zip(jose_header, decrypted, :decompress)
          successful_recipients << index
          break
        rescue StandardError
          failed_recipients << index
        end
      end

      raise InvalidData, 'No recipient could decrypt the message' unless plaintext

      DecryptionResult.new(
        plaintext: plaintext,
        successful_recipients: successful_recipients,
        failed_recipients: failed_recipients
      )
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity

    private

    def build_jose_header(protected_header, unprotected_header, recipient_header)
      result = {}
      result.merge!(protected_header.transform_keys(&:to_s)) if protected_header
      result.merge!(unprotected_header.transform_keys(&:to_s)) if unprotected_header
      result.merge!(recipient_header.transform_keys(&:to_s)) if recipient_header
      result
    end

    def normalize_keys(keys)
      case keys
      when Hash
        keys.transform_keys(&:to_s)
      when Array
        keys.each_with_index.to_h { |k, i| [i.to_s, k] }
      else
        { nil => keys }
      end
    end

    def select_key(key_map, jose_header)
      kid = jose_header['kid']
      if kid && key_map.key?(kid)
        key_map[kid]
      elsif key_map.key?(nil)
        key_map[nil]
      else
        key_map.values.first
      end
    end

    # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def validate_header_no_duplicates!(protected_header, unprotected_header, recipient_header)
      all_keys = []
      all_keys.concat(protected_header.keys.map(&:to_s)) if protected_header
      all_keys.concat(unprotected_header.keys.map(&:to_s)) if unprotected_header
      all_keys.concat(recipient_header.keys.map(&:to_s)) if recipient_header

      duplicates = all_keys.group_by(&:itself).select { |_, v| v.size > 1 }.keys
      raise DecodeError, "Duplicate header parameters: #{duplicates.join(', ')}" if duplicates.any?
    end
    # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
  end
end
