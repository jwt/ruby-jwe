module JWE
  module Serialization
    class Compact
      def self.encode(header, encrypted_cek, iv, ciphertext, tag)
        [ header, encrypted_cek, iv, ciphertext, tag ].map { |piece| JWE::Base64::jwe_encode(piece) }.join '.'
      end

      def self.decode(payload)
        parts = payload.split('.')
        raise JWE::DecodeError.new('Not enaugh or too many segments') unless parts.length == 5

        parts.map do |part|
          JWE::Base64.jwe_decode(part)
        end
      end
    end
  end
end
