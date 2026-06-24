# frozen_string_literal: true

module JWE
  # Decryption result for JSON Serialization
  # Contains plaintext and information about successful/failed recipients
  DecryptionResult = Struct.new(:plaintext, :successful_recipients, :failed_recipients, keyword_init: true) do
    def initialize(plaintext:, successful_recipients: [], failed_recipients: [])
      super
    end
  end
end
