require 'jwe/zip/def'

module JWE
  # Message deflating algorithms namespace
  module Zip
    def self.for(zip)
      case zip
      when 'DEF'
        Def
      else
        raise NotImplementedError.new("Unsupported zip type: #{zip}")
      end
    end
  end
end
