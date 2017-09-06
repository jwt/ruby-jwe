require 'jwe/enc/aes_gcm'

module JWE
  module Enc
    # AES GCM 256 algorithm.
    class A256gcm
      include AesGcm

      def key_length
        32
      end

      def cipher_name
        'aes-256-gcm'
      end
    end
  end
end
