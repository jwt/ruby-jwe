# frozen_string_literal: true

require 'jwe/zip/def'

module JWE
  # Message deflating algorithms namespace
  module Zip
    extend JWE::NameResolver

    def self.for(zip)
      const_get(param_to_class_name(zip))
    rescue NameError
      raise NotImplementedError.new("Unsupported zip type: #{zip}")
    end
  end
end
