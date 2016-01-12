require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'

Dir[File.dirname(__FILE__) + '/jwe/alg/*.rb'].each { |alg| require alg }
Dir[File.dirname(__FILE__) + '/jwe/enc/*.rb'].each { |enc| require enc }
Dir[File.dirname(__FILE__) + '/jwe/zip/*.rb'].each { |enc| require enc }

module JWE
  class NotImplementedError < Exception; end
  class BadCEK < Exception; end
  class InvalidData < Exception; end
end
