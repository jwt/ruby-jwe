require 'jwe/base64'

module JWE
  describe Base64 do
    describe '.jwe_encode' do
      it 'encodes the payload using the urlsafe encoding' do
        # "me?" encodes to "bWU/" in standard encoding
        expect(Base64.jwe_encode("me?")).to_not include '/'
      end

      it 'strips the standard padding' do
        expect(Base64.jwe_encode("a")).to_not end_with '='
      end
    end

    describe '.jwe_decode' do
      it 'decodes the payload using the urlsafe encoding' do
        # "me?" encodes to "bWU/" in standard encoding
        expect(Base64.jwe_decode("bWU_")).to eq "me?"
      end

      it 'fixes the padding' do
        expect(Base64.jwe_decode("YQ")).to eq "a"
      end
    end
  end
end
