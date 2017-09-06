module JWE
  module Enc
    class Cipher
      def self.for(cipher_name)
        OpenSSL::Cipher.new(cipher_name)
      rescue RuntimeError
        raise JWE::NotImplementedError.new("The version of OpenSSL linked to your Ruby does not support the cipher #{cipher_name}.")
      end
    end
  end
end
