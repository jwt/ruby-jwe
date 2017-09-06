require 'jwe/enc/cipher'

module JWE
  module Enc
    # Abstract AES in Block cipher mode, with message signature for different key sizes.
    module AesCbcHs
      attr_accessor :cek
      attr_accessor :iv
      attr_accessor :tag

      def initialize(cek = nil, iv = nil)
        self.iv = iv
        self.cek = cek
      end

      def encrypt(cleartext, authenticated_data)
        raise JWE::BadCEK.new("The supplied key is invalid. Required length: #{key_length}") if cek.length != key_length

        cipher.encrypt
        cipher.key = enc_key
        cipher.iv = iv

        ciphertext = cipher.update(cleartext) + cipher.final
        length = [authenticated_data.length * 8].pack('Q>') # 64bit big endian

        to_sign = authenticated_data + iv + ciphertext + length
        signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(hash_name), mac_key, to_sign)
        self.tag = signature[0...mac_key.length]

        ciphertext
      end

      def decrypt(ciphertext, authenticated_data)
        raise JWE::BadCEK.new("The supplied key is invalid. Required length: #{key_length}") if cek.length != key_length

        length = [authenticated_data.length * 8].pack('Q>') # 64bit big endian
        to_sign = authenticated_data + iv + ciphertext + length
        signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(hash_name), mac_key, to_sign)
        if signature[0...mac_key.length] != tag
          raise JWE::InvalidData.new('Authentication tag verification failed')
        end

        cipher.decrypt
        cipher.key = enc_key
        cipher.iv = iv

        cipher.update(ciphertext) + cipher.final
      rescue OpenSSL::Cipher::CipherError
        raise JWE::InvalidData.new('Invalid ciphertext or authentication tag')
      end

      def iv
        @iv ||= SecureRandom.random_bytes(16)
      end

      def cek
        @cek ||= SecureRandom.random_bytes(key_length)
      end

      def mac_key
        cek[0...key_length / 2]
      end

      def enc_key
        cek[key_length / 2..-1]
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
