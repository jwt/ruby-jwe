require 'jwe/zip/def'

describe JWE::Zip::Def do
  it 'deflates and inflates to original payload' do
    deflate = JWE::Zip::Def.new
    deflated = deflate.compress("hello world")
    expect(deflate.decompress(deflated)).to eq "hello world"
  end
end
