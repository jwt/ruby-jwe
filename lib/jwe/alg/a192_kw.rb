require 'jwe/alg/aes_kw'

module JWE
  module Alg
    class A192Kw
      include AesKw

      def cipher_name
        'AES-192-ECB'
      end
    end
  end
end
