# frozen_string_literal: true

module JWE
  # Serialization namespace.
  module Serialization
    # The default and suggested way of serializing JWE messages.
    class Compact
      def self.encode(header, encrypted_cek, iv, ciphertext, tag)
        [header, encrypted_cek, iv, ciphertext, tag].map { |piece| JWE::Base64.jwe_encode(piece) }.join '.'
      end

      def self.decode(payload)
        parts = payload.split('.')
        raise JWE::DecodeError.new('Not enough or too many segments') unless parts.length == 5

        parts.map do |part|
          JWE::Base64.jwe_decode(part)
        end
      end
    end
  end
end
