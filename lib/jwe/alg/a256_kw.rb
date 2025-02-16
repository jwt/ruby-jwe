# frozen_string_literal: true

require 'jwe/alg/aes_kw'

module JWE
  module Alg
    # AES-256 Key Wrapping algorithm
    class A256kw
      include AesKw

      def cipher_name
        'AES-256-ECB'
      end
    end
  end
end
