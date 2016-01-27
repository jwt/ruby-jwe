module JWE
  module Alg
    class Dir
      attr_accessor :key

      def initialize(key)
        self.key = key
      end

      def encrypt(_cek)
        ''
      end

      def decrypt(_encrypted_cek)
        key
      end
    end
  end
end
