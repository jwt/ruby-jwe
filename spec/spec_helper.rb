require 'codeclimate-test-reporter'
CodeClimate::TestReporter.start

require 'rspec'
require 'jwe'

RSpec.configure do |config|
  config.order = 'random'
end
