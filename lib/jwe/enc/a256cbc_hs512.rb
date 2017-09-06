require 'jwe/enc/aes_cbc_hs'

module JWE
  module Enc
    # AES CBC 256 + SHA512 message verification algorithm.
    class A256cbcHs512
      include AesCbcHs

      def key_length
        64
      end

      def cipher_name
        'AES-256-CBC'
      end

      def hash_name
        'sha512'
      end
    end
  end
end
