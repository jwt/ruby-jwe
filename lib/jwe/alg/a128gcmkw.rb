# frozen_string_literal: true

require 'jwe/alg/aes_gcm'

module JWE
  module Alg
    # AES-128 key wrap with GCM algorithm
    class A128gcmkw < Base
      include AesGcm

      def initialize(key, iv = nil)
        super
      end

      private

      def key_length
        16
      end

      def cipher_name
        'aes-128-gcm'
      end

      def required_additional_header_parameters?
        true
      end
    end
  end
end
