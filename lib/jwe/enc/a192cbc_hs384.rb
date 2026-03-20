# frozen_string_literal: true

require 'jwe/enc/base'
require 'jwe/enc/aes_cbc_hs'

module JWE
  module Enc
    # AES CBC 192 + SHA384 message verification algorithm.
    class A192cbcHs384 < Base
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
