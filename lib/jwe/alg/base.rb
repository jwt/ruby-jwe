# frozen_string_literal: true

module JWE
  module Alg
    # Base class for key encryption algorithms
    class Base
      include JWE::NameResolver

      def encrypt(_cek)
        raise NotImplementedError, "#{self.class} must implement #encrypt"
      end

      def decrypt(_encrypted_cek)
        raise NotImplementedError, "#{self.class} must implement #decrypt"
      end

      def need_additional_header_parameters?
        false
      end
    end
  end
end
