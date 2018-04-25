require 'jwe/alg/aes_kw'

module JWE
  module Alg
    # AES-192 Key Wrapping algorithm
    class A192kw
      include AesKw

      def cipher_name
        'AES-192-ECB'
      end
    end
  end
end
