# frozen_string_literal: true

module JWE
  module Alg
    # Direct (no-op) key encryption algorithm.
    class Dir < Base
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

      def class_name_to_param
        'dir'
      end
    end
  end
end
