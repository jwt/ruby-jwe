# frozen_string_literal: true

require 'zlib'

module JWE
  module Zip
    # Deflate algorithm.
    class Def
      # Upper bound for the size of decompressed content, guarding against
      # decompression bombs.
      MAX_DECOMPRESSED_SIZE = 1024 * 1024

      def compress(payload)
        zlib = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
        zlib.deflate(payload, Zlib::FINISH)
      end

      # Was using RFC 1950 instead of 1951.
      def decompress(payload)
        decompress_bounded(payload, Zlib::MAX_WBITS)

      # Keeping compatibility for old encoded tokens
      rescue Zlib::DataError
        decompress_bounded(payload, -Zlib::MAX_WBITS)
      end

      private

      def decompress_bounded(payload, window_bits)
        inflater = Zlib::Inflate.new(window_bits)
        output = String.new(encoding: Encoding::BINARY)

        inflater.inflate(payload) { |chunk| append_bounded(output, chunk) }
        append_bounded(output, inflater.finish)

        output
      ensure
        inflater.close if inflater && !inflater.closed?
      end

      def append_bounded(output, chunk)
        raise JWE::InvalidData, 'Decompressed content exceeds the maximum size' if chunk.bytesize > MAX_DECOMPRESSED_SIZE - output.bytesize

        output << chunk
      end
    end
  end
end
