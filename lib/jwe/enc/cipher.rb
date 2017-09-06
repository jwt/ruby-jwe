module JWE
  module Enc
    # Helper to get OpenSSL cipher instance from a string.
    module Cipher
      class << self
        def for(cipher_name)
          OpenSSL::Cipher.new(cipher_name)
        rescue RuntimeError
          raise JWE::NotImplementedError.new("The version of OpenSSL linked to your Ruby does not support the cipher #{cipher_name}.")
        end
      end
    end
  end
end
