require 'zlib'

module JWE
  module Zip
    class Def
      def compress(payload)
        Zlib::Deflate.deflate(payload)
      end

      def decompress(payload)
        Zlib::Inflate.inflate(payload)
      end
    end
  end
end
