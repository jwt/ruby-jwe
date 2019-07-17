require 'rspec'
require 'simplecov'

require 'jwe'

SimpleCov.start if ENV['COVERAGE']

RSpec.configure do |config|
  config.order = 'random'
end
