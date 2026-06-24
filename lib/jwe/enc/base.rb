# frozen_string_literal: true

module JWE
  module Enc
    # Base class for content encryption algorithms
    class Base
      include JWE::NameResolver

      def encrypt(_cleartext, _authenticated_data)
        raise NotImplementedError, "#{self.class} must implement #encrypt"
      end

      def decrypt(_ciphertext, _authenticated_data)
        raise NotImplementedError, "#{self.class} must implement #decrypt"
      end
    end
  end
end
