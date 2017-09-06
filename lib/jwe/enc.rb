require 'jwe/enc/a128cbc_hs256'
require 'jwe/enc/a192cbc_hs384'
require 'jwe/enc/a256cbc_hs512'
require 'jwe/enc/a128gcm'
require 'jwe/enc/a192gcm'
require 'jwe/enc/a256gcm'

module JWE
  # Content encryption algorithms namespace
  module Enc
    def self.for(enc)
      const_get(JWE.param_to_class_name(enc))
    rescue NameError
      raise NotImplementedError.new("Unsupported enc type: #{enc}")
    end
  end
end
