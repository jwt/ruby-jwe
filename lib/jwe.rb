require 'base64'
require 'json'
require 'openssl'
require 'securerandom'

require 'jwe/base64'
require 'jwe/serialization/compact'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/zip'

module JWE
  class DecodeError < Exception; end
  class NotImplementedError < Exception; end
  class BadCEK < Exception; end
  class InvalidData < Exception; end
end
