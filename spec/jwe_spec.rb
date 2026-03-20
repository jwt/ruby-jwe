# frozen_string_literal: true

describe JWE do
  let(:plaintext) { 'The true sign of intelligence is not knowledge but imagination.' }
  let(:rsa_key) { OpenSSL::PKey::RSA.new File.read("#{File.dirname(__FILE__)}/keys/rsa.pem") }
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
      aes_password = SecureRandom.random_bytes(16)
      encrypted = JWE.encrypt(plaintext, aes_password, alg: 'dir')
      result = JWE.decrypt(encrypted, aes_password)

      expect(result).to eq plaintext
    end
  end

  describe 'when using extra headers' do
    it 'roundtrips' do
      encrypted = JWE.encrypt(plaintext, rsa_key, kid: 'some-kid-1')
      result = JWE.decrypt(encrypted, rsa_key)
      header, = JWE::Serialization::Compact.decode(encrypted)
      header = JSON.parse(header)

      expect(header['kid']).to eq 'some-kid-1'
      expect(result).to eq plaintext
    end
  end

  describe 'when using A128GCMKW algorithm' do
    it 'roundtrips' do
      aes_key = SecureRandom.random_bytes(16)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A128GCMKW')
      result = JWE.decrypt(encrypted, aes_key)

      expect(result).to eq plaintext
    end

    it 'includes iv and tag in header' do
      aes_key = SecureRandom.random_bytes(16)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A128GCMKW')
      header, = JWE::Serialization::Compact.decode(encrypted)
      header = JSON.parse(header)

      expect(header['alg']).to eq 'A128GCMKW'
      expect(header).to have_key('iv')
      expect(header).to have_key('tag')
    end
  end

  describe 'when using A192GCMKW algorithm' do
    it 'roundtrips' do
      aes_key = SecureRandom.random_bytes(24)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A192GCMKW', enc: 'A192GCM')
      result = JWE.decrypt(encrypted, aes_key)

      expect(result).to eq plaintext
    end
  end

  describe 'when using A256GCMKW algorithm with A256GCM encryption' do
    it 'roundtrips' do
      aes_key = SecureRandom.random_bytes(32)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A256GCMKW', enc: 'A256GCM')
      result = JWE.decrypt(encrypted, aes_key)

      expect(result).to eq plaintext
    end

    it 'includes iv and tag in header' do
      aes_key = SecureRandom.random_bytes(32)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A256GCMKW', enc: 'A256GCM')
      header, = JWE::Serialization::Compact.decode(encrypted)
      header = JSON.parse(header)

      expect(header['alg']).to eq 'A256GCMKW'
      expect(header['enc']).to eq 'A256GCM'
      expect(header).to have_key('iv')
      expect(header).to have_key('tag')
    end

    it 'works with compression' do
      aes_key = SecureRandom.random_bytes(32)
      encrypted = JWE.encrypt(plaintext, aes_key, alg: 'A256GCMKW', enc: 'A256GCM', zip: 'DEF')
      result = JWE.decrypt(encrypted, aes_key)

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
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad enc' do
    hdr = { alg: 'A192CBC-HS384', enc: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when decoding a bad zip' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, rsa_key) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key' do
    expect { JWE.encrypt(plaintext, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, nil) }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a blank key' do
    expect { JWE.encrypt(plaintext, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a blank key' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, "  \t \n ") }.to raise_error(ArgumentError)
  end

  it 'raises when encrypting with a nil key with `dir` algorithm' do
    expect { JWE.encrypt(plaintext, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end

  it 'raises when decrypting with a nil key with `dir` algorithm' do
    hdr = { alg: 'A192CBC-HS384', enc: 'A128GCM', zip: 'TEST' }
    payload = "#{JWE::Base64.jwe_encode(hdr.to_json)}.QY.QY.QY.QY"
    expect { JWE.decrypt(payload, nil, alg: 'dir') }.to raise_error(ArgumentError)
  end
end
