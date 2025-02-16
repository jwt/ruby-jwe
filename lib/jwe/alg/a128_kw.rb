# frozen_string_literal: true

require 'jwe/alg/aes_kw'

module JWE
  module Alg
    # AES-128 Key Wrapping algorithm
    class A128kw
      include AesKw

      def cipher_name
        'AES-128-ECB'
      end
    end
  end
end
