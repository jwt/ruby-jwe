require 'jwe/enc/a128cbc_hs256'
require 'jwe/enc/a192cbc_hs384'
require 'jwe/enc/a256cbc_hs512'
require 'jwe/enc/a128gcm'
require 'jwe/enc/a192gcm'
require 'jwe/enc/a256gcm'

module JWE
  module Enc
    def self.for(enc)
      klass = enc.gsub(/[-\+]/, '_').downcase.sub(/^[a-z\d]*/) { $&.capitalize }
      klass.gsub!(/_([a-z\d]*)/i) { $1.capitalize }
      const_get(klass)

    rescue NameError
      raise NotImplementedError.new("Unsupported enc type: #{enc}")
    end
  end
end
