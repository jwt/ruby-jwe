# frozen_string_literal: true

module JWE
  module Alg
    # RSA-OAEP-256 key encryption algorithm.
    class RsaOaep256
      attr_accessor :key

      def initialize(key)
        self.key = key
      end

      def encrypt(cek)
        key.encrypt(cek, { rsa_padding_mode: 'oaep', rsa_oaep_md: 'sha256' })
      end

      def decrypt(encrypted_cek)
        key.decrypt(encrypted_cek, { rsa_padding_mode: 'oaep', rsa_oaep_md: 'sha256' })
      end
    end
  end
end
