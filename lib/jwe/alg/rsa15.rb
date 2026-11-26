# frozen_string_literal: true

module JWE
  module Alg
    # RSA RSA with PKCS1 v1.5 algorithm.
    class Rsa15
      attr_accessor :key

      # Expected length of the content encryption key. When set, decryption
      # failures are masked with a random CEK of this length (implicit
      # rejection, RFC 7516 section 11.5), so a malformed encrypted key is
      # indistinguishable from a failed content authentication.
      attr_accessor :cek_length

      def initialize(key)
        self.key = key
      end

      def encrypt(cek)
        key.public_encrypt(cek)
      end

      def decrypt(encrypted_cek)
        return key.private_decrypt(encrypted_cek) if cek_length.nil?

        fallback_cek = SecureRandom.random_bytes(cek_length)
        cek = unwrap(encrypted_cek)

        return fallback_cek unless cek && cek.bytesize == cek_length

        cek
      end

      private

      def unwrap(encrypted_cek)
        key.private_decrypt(encrypted_cek)
      rescue OpenSSL::PKey::PKeyError
        nil
      end
    end
  end
end
