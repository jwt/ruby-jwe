require 'jwe/alg/a128_kw'
require 'jwe/alg/a192_kw'
require 'jwe/alg/a256_kw'
require 'jwe/alg/dir'
require 'jwe/alg/rsa_oaep'
require 'jwe/alg/rsa15'

module JWE
  # Key encryption algorithms namespace
  module Alg
    def self.for(alg)
      const_get(JWE.param_to_class_name(alg))
    rescue NameError
      raise NotImplementedError.new("Unsupported alg type: #{alg}")
    end

    def self.encrypt_cek(alg, key, cek)
      self.for(alg).new(key).encrypt(cek)
    end

    def self.decrypt_cek(alg, key, encrypted_cek)
      self.for(alg).new(key).decrypt(encrypted_cek)
    end
  end
end
