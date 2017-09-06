require 'jwe/enc/aes_cbc_hs'

module JWE
  module Enc
    # AES CBC 128 + SHA256 message verification algorithm.
    class A128cbcHs256
      include AesCbcHs

      def key_length
        32
      end

      def cipher_name
        'AES-128-CBC'
      end

      def hash_name
        'sha256'
      end
    end
  end
end
