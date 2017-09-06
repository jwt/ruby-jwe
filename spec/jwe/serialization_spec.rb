describe JWE::Serialization::Compact do
  describe '#encode' do
    it 'returns components base64ed and joined with a dot' do
      components = %w[a b c d e]
      expect(JWE::Serialization::Compact.encode(*components)).to eq 'YQ.Yg.Yw.ZA.ZQ'
    end
  end

  describe '#decode' do
    it 'returns an array with the 5 components' do
      expect(JWE::Serialization::Compact.decode('YQ.Yg.Yw.ZA.ZQ')).to eq %w[a b c d e]
    end

    it 'raises an error when passed a badly formatted payload' do
      expect { JWE::Serialization::Compact.decode('YQ.YQ.Yg.Yw.ZA.ZQ') }.to raise_error(JWE::DecodeError)
    end
  end
end
