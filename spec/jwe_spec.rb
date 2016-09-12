describe JWE do
  let(:plaintext) { 'The true sign of intelligence is not knowledge but imagination.' }
  let(:rsa_key) { OpenSSL::PKey::RSA.new File.read(File.dirname(__FILE__) + '/keys/rsa.pem') }
  let(:password) { SecureRandom.random_bytes(64) }

  it 'roundtrips' do
    encrypted = JWE.encrypt(plaintext, rsa_key)
    result = JWE.decrypt(encrypted, rsa_key)

    expect(result).to eq plaintext
  end

  describe 'when using DEF compression' do
    it 'roundtrips' do
      encrypted = JWE.encrypt(plaintext, rsa_key, zip: 'DEF')
      result = JWE.decrypt(encrypted, rsa_key)

      expect(result).to eq plaintext
    end
  end

  describe 'when using dir alg method' do
    it 'roundtrips' do
      encrypted = JWE.encrypt(plaintext, password, alg: 'dir')
      result = JWE.decrypt(encrypted, password)

      expect(result).to eq plaintext
    end
  end

  it 'raises when passed a bad alg' do
    expect { JWE.encrypt(plaintext, rsa_key, alg: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when passed a bad enc' do
    expect { JWE.encrypt(plaintext, rsa_key, enc: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when passed a bad zip' do
    expect { JWE.encrypt(plaintext, rsa_key, zip: 'TEST') }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad alg' do
    hdr = { alg: 'TEST', enc: 'A128GCM' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad enc' do
    hdr = { alg: 'A192CBC-HS384', enc: 'TEST' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad zip' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key' do
    expect { JWE.encrypt(plaintext, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a blank key' do
    expect { JWE.encrypt(plaintext, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a blank key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key with `dir` algorithm' do
    expect { JWE.encrypt(plaintext, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key with `dir` algorithm' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = JWE::Base64.jwe_encode(hdr.to_json) + '.QY.QY.QY.QY'
    expect { JWE.decrypt(payload, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end
end
