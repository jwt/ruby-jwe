# frozen_string_literal: true

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
  s.homepage    = 'https://github.com/jwt/ruby-jwe'
  s.license     = 'MIT'

  s.files = `git ls-files`.split("\n")
  s.require_paths = %w[lib]

  s.required_ruby_version = '>= 2.5.0'

  spec.metadata = {
    'bug_tracker_uri' => 'https://github.com/jwt/ruby-jwe/issues',
    'changelog_uri' => "https://github.com/jwt/ruby-jwe/blob/v#{JWE::VERSION}/CHANGELOG.md",
    'rubygems_mfa_required' => 'true'
  }
  s.add_dependency 'base64'
end
