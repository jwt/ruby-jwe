lib = File.expand_path('../lib/', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'jwe/version'

Gem::Specification.new do |s|
  s.name        = 'jwe'
  s.version     = JWE::VERSION
  s.summary     = 'JSON Web Encryption implementation in Ruby'
  s.description = 'A Ruby implementation of the RFC 7516 JSON Web Encryption (JWE) standard'
  s.authors     = ['Francesco Boffa']
  s.email       = 'fra.boffa@gmail.com'
  s.homepage    = 'http://github.com/aomega08/jwe'
  s.license     = 'MIT'

  s.files = `git ls-files`.split("\n")
  s.require_paths = %w(lib)

  s.required_ruby_version = '>= 2.0.0'

  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'simplecov'
end
