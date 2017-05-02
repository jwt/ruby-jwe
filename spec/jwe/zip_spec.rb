require 'jwe/zip/def'

describe JWE::Zip do
  describe '.for' do
    it 'returns a class for the specified zip' do
      expect(JWE::Zip.for('DEF')).to eq JWE::Zip::Def
    end

    it 'raises an error for a not-implemented zip' do
      expect { JWE::Zip.for('BZIP2+JPG') }.to raise_error(JWE::NotImplementedError)
    end
  end
end

describe JWE::Zip::Def do
  it 'deflates and inflates to original payload' do
    deflate = JWE::Zip::Def.new
    deflated = deflate.compress('hello world')
    expect(deflate.decompress(deflated)).to eq 'hello world'
  end

  it 'can deflate an RFC 1950 compressed message' do
    deflated = Zlib::Deflate.deflate('hello world')
    deflate = JWE::Zip::Def.new
    expect(deflate.decompress(deflated)).to eq 'hello world'
  end
end
