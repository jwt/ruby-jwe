require 'jwe/alg/dir'
require 'jwe/alg/rsa_oaep'
require 'jwe/alg/rsa15'

module JWE
  module Alg
    def self.for(alg)
      klass = alg.gsub(/[-\+]/, '_').downcase.sub(/^[a-z\d]*/) { $&.capitalize }
      klass.gsub!(/_([a-z\d]*)/i) { Regexp.last_match(1).capitalize }
      const_get(klass)

    rescue NameError
      raise NotImplementedError.new("Unsupported alg type: #{alg}")
    end
  end
end
