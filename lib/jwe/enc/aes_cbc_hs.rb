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

        ciphertext = cipher_round(:encrypt, iv, cleartext)

        signature = generate_tag(authenticated_data, iv, ciphertext)
        self.tag = signature

        ciphertext
      end

      def decrypt(ciphertext, authenticated_data)
        raise JWE::BadCEK, "The supplied key is invalid. Required length: #{key_length}" if cek.length != key_length

        signature = generate_tag(authenticated_data, iv, ciphertext)
        if signature != tag
          raise JWE::InvalidData, 'Authentication tag verification failed'
        end

        cipher_round(:decrypt, iv, ciphertext)
      rescue OpenSSL::Cipher::CipherError
        raise JWE::InvalidData, 'Invalid ciphertext or authentication tag'
      end

      def cipher_round(direction, iv, data)
        cipher.send(direction)
        cipher.key = enc_key
        cipher.iv = iv

        cipher.update(data) + cipher.final
      end

      def generate_tag(authenticated_data, iv, ciphertext)
        length = [authenticated_data.length * 8].pack('Q>') # 64bit big endian
        to_sign = authenticated_data + iv + ciphertext + length
        signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new(hash_name), mac_key, to_sign)

        signature[0...mac_key.length]
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
