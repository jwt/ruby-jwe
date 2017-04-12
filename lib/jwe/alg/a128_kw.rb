require 'jwe/alg/aes_kw'

module JWE
  module Alg
    class A128Kw
      include AesKw

      def cipher_name
        'AES-128-ECB'
      end
    end
  end
end
