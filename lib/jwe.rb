require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'

module JWE
  class DecodeError < RuntimeError; end
  class NotImplementedError < RuntimeError; end
  class BadCEK < RuntimeError; end
  class InvalidData < RuntimeError; end

  VALID_ALG = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256', 'A128KW', 'A192KW', 'A256KW', 'dir', 'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW', 'A128GCMKW', 'A192GCMKW', 'A256GCMKW', 'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW'].freeze
  VALID_ENC = ['A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512', 'A128GCM', 'A192GCM', 'A256GCM'].freeze
  VALID_ZIP = ['DEF'].freeze

  def self.encrypt(payload, key, alg: 'RSA-OAEP', enc: 'A128GCM', **more_headers)
    check_params(alg, enc, more_headers[:zip], key)

    more_headers.delete(:zip) if more_headers[:zip] == ''

    header = { alg: alg, enc: enc }
    header.merge!(more_headers)

    cipher = Enc.for(enc).new
    cipher.cek = key if alg == 'dir'

    payload = Zip.for(more_headers[:zip]).new.compress(payload) if more_headers[:zip]

    ciphertext = cipher.encrypt(payload, Base64.jwe_encode(header.to_json))
    encrypted_cek = Alg.for(alg).new(key).encrypt(cipher.cek)

    Serialization::Compact.encode(header.to_json, encrypted_cek, cipher.iv, ciphertext, cipher.tag)
  end

  def self.decrypt(payload, key)
    header, enc_key, iv, ciphertext, tag = Serialization::Compact.decode(payload)
    header = JSON.parse(header)

    check_params(header['alg'], header['enc'], header['zip'], key)

    cek = Alg.for(header['alg']).new(key).decrypt(enc_key)
    cipher = Enc.for(header['enc']).new(cek, iv)
    cipher.tag = tag

    plaintext = cipher.decrypt(ciphertext, payload.split('.').first)

    if header['zip']
      Zip.for(header['zip']).new.decompress(plaintext)
    else
      plaintext
    end
  end

  def self.check_params(alg, enc, zip, key)
    check_alg(alg)
    check_enc(enc)
    check_zip(zip)
    check_key(key)
  end

  def self.check_alg(alg)
    raise ArgumentError.new("\"#{alg}\" is not a valid alg method") unless VALID_ALG.include?(alg)
  end

  def self.check_enc(enc)
    raise ArgumentError.new("\"#{enc}\" is not a valid enc method") unless VALID_ENC.include?(enc)
  end

  def self.check_zip(zip)
    raise ArgumentError.new("\"#{zip}\" is not a valid zip method") unless zip.nil? || zip == '' || VALID_ZIP.include?(zip)
  end

  def self.check_key(key)
    raise ArgumentError.new('The key must not be nil or blank') if key.nil? || (key.is_a?(String) && key.strip == '')
  end
end
