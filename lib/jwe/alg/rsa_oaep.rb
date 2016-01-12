module JWE
  module Alg
    class RsaOaep
      attr_accessor :key

      def initialize(key)
        self.key = key
      end

      def encrypt(cek)
        key.public_encrypt(cek, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      end

      def decrypt(encrypted_cek)
        key.private_decrypt(encrypted_cek, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      end
    end
  end
end
