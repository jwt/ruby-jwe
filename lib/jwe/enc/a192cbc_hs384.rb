require 'jwe/enc/aes_cbc_hs'

module JWE
  module Enc
    class A192cbcHs384
      include AesCbcHs

      def key_length
        48
      end

      def cipher_name
        'AES-192-CBC'
      end

      def hash_name
        'sha384'
      end
    end
  end
end
