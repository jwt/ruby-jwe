require 'jwe/zip/def'

module JWE
  module Zip
    def self.for(zip)
      const_get(JWE.param_to_class_name(zip))

    rescue NameError
      raise NotImplementedError.new("Unsupported zip type: #{zip}")
    end
  end
end
