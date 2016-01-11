require 'jwe/enc/aes_gcm'

module JWE
  module Enc
    class A128gcm
      include AesGcm

      def key_length
        16
      end

      def cipher_name
        'aes-128-gcm'
      end
    end
  end
end
