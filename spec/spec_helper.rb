require 'rspec'
require 'jwe'
require 'codeclimate-test-reporter'

CodeClimate::TestReporter.start

RSpec.configure do |config|
  config.order = 'random'
end
