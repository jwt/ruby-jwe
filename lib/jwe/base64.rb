module JWE
  module Base64
    def self.jwe_encode(payload)
      ::Base64.urlsafe_encode64(payload).delete('=')
    end

    def self.jwe_decode(payload)
      padlen = 4 - (payload.length % 4)
      if padlen < 4
        pad = '=' * padlen
        payload += pad
      end
      ::Base64.urlsafe_decode64(payload)
    end
  end
end
