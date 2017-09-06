require 'jwe/enc/cipher'

module JWE
  module Enc
    # Abstract AES in Galois Counter mode for different key sizes.
    module AesGcm
      attr_accessor :cek
      attr_accessor :iv
      attr_accessor :tag

      def initialize(cek = nil, iv = nil)
        self.iv = iv
        self.cek = cek
      end

      def encrypt(cleartext, authenticated_data)
        raise JWE::BadCEK.new("The supplied key is too short. Required length: #{key_length}") if cek.length < key_length

        cipher.encrypt
        cipher.key = cek
        cipher.iv = iv
        cipher.auth_data = authenticated_data

        ciphertext = cipher.update(cleartext) + cipher.final
        self.tag = cipher.auth_tag

        ciphertext
      end

      def decrypt(ciphertext, authenticated_data)
        raise JWE::BadCEK.new("The supplied key is too short. Required length: #{key_length}") if cek.length < key_length

        cipher.decrypt
        cipher.key = cek
        cipher.iv = iv
        cipher.auth_tag = tag
        cipher.auth_data = authenticated_data

        cipher.update(ciphertext) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise JWE::InvalidData.new('Invalid ciphertext or authentication tag')
      end

      def iv
        @iv ||= SecureRandom.random_bytes(12)
      end

      def cek
        @cek ||= SecureRandom.random_bytes(key_length)
      end

      def cipher
        @cipher ||= Cipher.for(cipher_name)
      end

      def tag
        @tag || ''
      end

      def self.included(base)
        base.extend(ClassMethods)
      end

      # Provides availability checks for Key Encryption algorithms
      module ClassMethods
        def available?
          new.cipher
          true
        rescue JWE::NotImplementedError
          false
        end
      end
    end
  end
end
