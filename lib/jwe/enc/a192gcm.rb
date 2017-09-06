require 'jwe/enc/aes_gcm'

module JWE
  module Enc
    # AES GCM 192 algorithm.
    class A192gcm
      include AesGcm

      def key_length
        24
      end

      def cipher_name
        'aes-192-gcm'
      end
    end
  end
end
