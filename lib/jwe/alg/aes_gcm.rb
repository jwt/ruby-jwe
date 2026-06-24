# frozen_string_literal: true

require 'jwe/enc/cipher'

module JWE
  module Alg
    # Abstract AES in Galois Counter mode for different key sizes.
    module AesGcm
      attr_accessor :iv, :cek, :tag

      def initialize(cek, iv = nil)
        self.iv = iv || SecureRandom.random_bytes(12)
        self.cek = cek
        self.tag = ''
      end

      def encrypt(cleartext)
        raise JWE::BadCEK, "The supplied key is too short. Required length: #{key_length}" if cek.length < key_length

        setup_cipher(:encrypt)
        ciphertext = cipher.update(cleartext) + cipher.final
        self.tag = cipher.auth_tag

        ciphertext
      end

      def decrypt(ciphertext)
        raise JWE::BadCEK, "The supplied key is too short. Required length: #{key_length}" if cek.length < key_length

        setup_cipher(:decrypt)
        cipher.update(ciphertext) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise JWE::InvalidData, 'Invalid ciphertext or authentication tag'
      end

      def setup_cipher(direction)
        cipher.send(direction)
        cipher.key = cek
        cipher.iv = iv
        if direction == :decrypt
          raise JWE::InvalidData, 'Invalid ciphertext or authentication tag' unless tag.bytesize == 16

          cipher.auth_tag = tag
        end
        cipher.auth_data = ''
      end

      def cipher
        @cipher ||= OpenSSL::Cipher.new(cipher_name)
      rescue RuntimeError
        raise JWE::NotImplementedError.new("The version of OpenSSL linked to your Ruby does not support the cipher #{cipher_name}.")
      end

      def header_parameters
        {
          iv: JWE::Base64.jwe_encode(iv),
          tag: JWE::Base64.jwe_encode(tag)
        }
      end

      def need_additional_header_parameters?
        true
      end
    end
  end
end
