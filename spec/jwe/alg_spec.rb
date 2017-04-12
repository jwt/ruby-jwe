require 'jwe/alg/dir'
require 'jwe/alg/rsa_oaep'
require 'jwe/alg/rsa15'
require 'jwe/alg/a128_kw'
require 'jwe/alg/a192_kw'
require 'jwe/alg/a256_kw'
require 'openssl'

describe JWE::Alg do
  describe '.for' do
    it 'returns a class for the specified alg' do
      expect(JWE::Alg.for('RSA-OAEP')).to eq JWE::Alg::RsaOaep
    end

    it 'raises an error for a not-implemented alg' do
      expect { JWE::Alg.for('ERSA-4096-MAGIC') }.to raise_error(JWE::NotImplementedError)
    end
  end
end

describe JWE::Alg::Dir do
  # The direct encryption method does not Encrypt the CEK.
  # When building the final JWE object, the "Encrypted CEK" part is left blank

  describe '#encrypt' do
    it 'returns an empty string' do
      expect(JWE::Alg::Dir.new('whatever').encrypt('any')).to eq ''
    end
  end

  describe '#decrypt' do
    it 'returns the original key' do
      expect(JWE::Alg::Dir.new('whatever').decrypt('any')).to eq 'whatever'
    end
  end
end

key_path = File.dirname(__FILE__) + '/../keys/rsa.pem'
key = OpenSSL::PKey::RSA.new File.read(key_path)

describe JWE::Alg::RsaOaep do
  let(:alg) { JWE::Alg::RsaOaep.new(key) }

  describe '#encrypt' do
    it 'returns an encrypted string' do
      expect(alg.encrypt('random key')).to_not eq 'random key'
    end
  end

  it 'decrypts the encrypted key to the original key' do
    ciphertext = alg.encrypt('random key')
    expect(alg.decrypt(ciphertext)).to eq 'random key'
  end
end

describe JWE::Alg::Rsa15 do
  let(:alg) { JWE::Alg::Rsa15.new(key) }

  describe '#encrypt' do
    it 'returns an encrypted string' do
      expect(alg.encrypt('random key')).to_not eq 'random key'
    end
  end

  it 'decrypts the encrypted key to the original key' do
    ciphertext = alg.encrypt('random key')
    expect(alg.decrypt(ciphertext)).to eq 'random key'
  end
end

[
  JWE::Alg::A128Kw,
  JWE::Alg::A192Kw,
  JWE::Alg::A256Kw
].each_with_index do |klass, i|
  describe klass do
    let(:kek) { SecureRandom.random_bytes(16 + i * 8) }
    let(:cek) { SecureRandom.random_bytes(32) }
    let(:alg) { klass.new(kek) }

    describe '#encrypt' do
      it 'returns an encrypted string' do
        expect(alg.encrypt(cek)).to_not eq cek
      end
    end

    it 'decrypts the encrypted key to the original key' do
      ciphertext = alg.encrypt(cek)
      expect(alg.decrypt(ciphertext)).to eq cek
    end

    it 'raises when trying to decrypt tampered keys' do
      alg = klass.new(kek, "\xA7\xA7\xA7\xA7\xA6\xA6\xA6\xA6")
      ciphertext = alg.encrypt(cek)

      bad_alg = klass.new(kek, "\xA7\xA7\xA7\xA7\xA7\xA7\xA7\xA7")
      expect { bad_alg.decrypt(ciphertext) }.to raise_error(StandardError)
    end
  end
end
