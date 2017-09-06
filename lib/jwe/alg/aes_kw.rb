require 'jwe/enc/cipher'

module JWE
  module Alg
    module AesKw
      attr_accessor :key
      attr_accessor :iv

      def initialize(key = nil, iv = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6")
        self.iv = iv.force_encoding('ASCII-8BIT')
        self.key = key.force_encoding('ASCII-8BIT')
      end

      def encrypt(cek)
        a = iv
        r = cek.scan(/.{8}/m)

        6.times do |j|
          r.length.times do |i|
            b = encrypt_round(a + r[i])

            a = b.chars.first(8).join
            r[i] = b.chars.last(8).join

            t = (r.length * j) + i + 1
            a = xor(a, t)
          end
        end

        ([a] + r).join
      end

      def decrypt(encrypted_cek)
        c = encrypted_cek.scan(/.{8}/m)
        a = c[0]

        r = c[1..c.length]

        5.downto(0) do |j|
          r.length.downto(1) do |i|
            t = (r.length * j) + i
            a = xor(a, t)

            b = decrypt_round(a + r[i - 1])

            a = b.chars.first(8).join
            r[i - 1] = b.chars.last(8).join
          end
        end

        if a != iv
          raise StandardError.new('The encrypted key has been tampered. Do not use this key.')
        end

        r.join
      end

      def cipher
        @cipher ||= Enc::Cipher.for(cipher_name)
      end

      def encrypt_round(data)
        cipher.encrypt
        cipher.key = key
        cipher.padding = 0
        cipher.update(data) + cipher.final
      end

      def decrypt_round(data)
        cipher.decrypt
        cipher.key = key
        cipher.padding = 0
        cipher.update(data) + cipher.final
      end

      def xor(data, t)
        t = ([0] * (data.length - 1)) + [t]
        data = data.chars.map(&:ord)

        data.zip(t).map { |a, b| (a ^ b).chr }.join
      end
    end
  end
end
