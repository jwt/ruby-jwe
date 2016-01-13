require 'jwe/zip/def'

module JWE
  module Zip
    def self.for(zip)
      klass = zip.gsub(/[-\+]/, '_').downcase.sub(/^[a-z\d]*/) { $&.capitalize }
      klass.gsub!(/_([a-z\d]*)/i) { $1.capitalize }
      const_get(klass)

    rescue NameError
      raise NotImplementedError.new("Unsupported zip type: #{zip}")
    end
  end
end
