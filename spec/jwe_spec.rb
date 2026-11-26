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

  describe 'when DEF compressed content exceeds the maximum size' do
    it 'raises JWE::InvalidData' do
      payload = 'a' * (JWE::Zip::Def::MAX_DECOMPRESSED_SIZE + 1)
      encrypted = JWE.encrypt(payload, rsa_key, zip: 'DEF')

      expect { JWE.decrypt(encrypted, rsa_key) }.to raise_error(JWE::InvalidData)
    end
  end

  describe 'when using RSA1_5 alg method' do
    let(:parts) { JWE.encrypt(plaintext, rsa_key, alg: 'RSA1_5', enc: enc).split('.') }

    %w[A128GCM A256CBC-HS512].each do |enc_name|
      context "with #{enc_name}" do
        let(:enc) { enc_name }

        it 'roundtrips' do
          expect(JWE.decrypt(parts.join('.'), rsa_key)).to eq plaintext
        end

        it 'raises JWE::InvalidData for a malformed encrypted key' do
          parts[1] = JWE::Base64.jwe_encode("\x00".b * (rsa_key.n.num_bits / 8))

          expect { JWE.decrypt(parts.join('.'), rsa_key) }.to raise_error(JWE::InvalidData)
        end

        it 'raises JWE::InvalidData for an encrypted key of the wrong length' do
          parts[1] = JWE::Base64.jwe_encode(rsa_key.public_encrypt('short'))

          expect { JWE.decrypt(parts.join('.'), rsa_key) }.to raise_error(JWE::InvalidData)
        end

        it 'raises JWE::InvalidData for a modified tag' do
          tag = JWE::Base64.jwe_decode(parts[4]).bytes
          tag[-1] ^= 1
          parts[4] = JWE::Base64.jwe_encode(tag.pack('C*'))

          expect { JWE.decrypt(parts.join('.'), rsa_key) }.to raise_error(JWE::InvalidData)
        end
      end
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
