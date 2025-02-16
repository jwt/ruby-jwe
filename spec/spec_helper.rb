# frozen_string_literal: true

require 'simplecov'
SimpleCov.start

require 'rspec'
require 'jwe'

RSpec.configure do |config|
  config.order = 'random'
end
