require 'zlib'

module JWE
  module Zip
    # Deflate algorithm.
    class Def
      def compress(payload)
        zlib = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
        zlib.deflate(payload, Zlib::FINISH)
      end

      # Was using RFC 1950 instead of 1951.
      def decompress(payload)
        Zlib::Inflate.inflate(payload)

      # Keeping compatibility for old encoded tokens
      rescue Zlib::DataError
        inflate = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        inflate.inflate(payload)
      end
    end
  end
end
