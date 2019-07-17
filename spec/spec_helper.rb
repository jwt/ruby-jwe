require 'rspec'
require 'simplecov'
require 'simplecov-json'
require 'codeclimate-test-reporter'
require 'codacy-coverage'

require 'jwe'

Codacy::Reporter.start

SimpleCov.configure do
  root File.join(File.dirname(__FILE__), '..')
  project_name 'Ruby JWE - Ruby JSON Web Encryption implementation'
  add_filter 'spec'
end

SimpleCov.start if ENV['COVERAGE']

RSpec.configure do |config|
  config.order = 'random'
end
