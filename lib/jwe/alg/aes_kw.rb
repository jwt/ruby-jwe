require 'jwe/enc/cipher'

module JWE
  module Alg
    # Generic AES Key Wrapping algorithm for any key size.
    module AesKw
      attr_accessor :key
      attr_accessor :iv

      def initialize(key = nil, iv = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6")
        self.iv = iv.force_encoding('ASCII-8BIT')
        self.key = key.force_encoding('ASCII-8BIT')
      end

      def encrypt(cek)
        a = iv
        r = cek.force_encoding('ASCII-8BIT').scan(/.{8}/m)

        6.times do |j|
          a, r = kw_encrypt_round(j, a, r)
        end

        ([a] + r).join
      end

      def kw_encrypt_round(j, a, r)
        r.length.times do |i|
          b = encrypt_round(a + r[i]).chars

          a, r[i] = a_ri(b)

          a = xor(a, (r.length * j) + i + 1)
        end

        [a, r]
      end

      def decrypt(encrypted_cek)
        c = encrypted_cek.force_encoding('ASCII-8BIT').scan(/.{8}/m)
        a, *r = c

        5.downto(0) do |j|
          a, r = kw_decrypt_round(j, a, r)
        end

        if a != iv
          raise StandardError.new('The encrypted key has been tampered. Do not use this key.')
        end

        r.join
      end

      def kw_decrypt_round(j, a, r)
        r.length.downto(1) do |i|
          a = xor(a, (r.length * j) + i)

          b = decrypt_round(a + r[i - 1]).chars

          a, r[i - 1] = a_ri(b)
        end

        [a, r]
      end

      def a_ri(b)
        [b.first(8).join, b.last(8).join]
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
