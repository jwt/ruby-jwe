require 'jwe/alg/a128_kw'
require 'jwe/alg/dir'
require 'jwe/alg/rsa_oaep'
require 'jwe/alg/rsa15'

module JWE
  module Alg
    def self.for(alg)
      const_get(JWE.param_to_class_name(alg))

    rescue NameError
      raise NotImplementedError.new("Unsupported alg type: #{alg}")
    end
  end
end
