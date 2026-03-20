# frozen_string_literal: true

require 'jwe/alg/aes_gcm'

module JWE
  module Alg
    # AES-256 key wrap with GCM algorithm
    class A256gcmkw < Base
      include AesGcm

      def initialize(key, iv = nil)
        super
      end

      private

      def key_length
        32
      end

      def cipher_name
        'aes-256-gcm'
      end

      def required_additional_header_parameters?
        true
      end
    end
  end
end
