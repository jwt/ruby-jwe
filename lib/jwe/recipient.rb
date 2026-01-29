# frozen_string_literal: true

module JWE
  # Recipient structure for JSON Serialization
  # Holds a key and optional per-recipient header
  Recipient = Struct.new(:key, :header, keyword_init: true) do
    def initialize(key:, header: {})
      super(key: key, header: header || {})
    end
  end
end
