module JWE
  module Alg
    # RSA RSA with PKCS1 v1.5 algorithm.
    class Rsa15
      attr_accessor :key

      def initialize(key)
        self.key = key
      end

      def encrypt(cek)
        key.public_encrypt(cek)
      end

      def decrypt(encrypted_cek)
        key.private_decrypt(encrypted_cek)
      end
    end
  end
end
