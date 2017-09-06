require 'jwe/enc/a128cbc_hs256'
require 'jwe/enc/a192cbc_hs384'
require 'jwe/enc/a256cbc_hs512'
require 'jwe/enc/a128gcm'
require 'jwe/enc/a192gcm'
require 'jwe/enc/a256gcm'

describe JWE::Enc do
  describe '.for' do
    it 'returns an instance for the specified enc' do
      expect(JWE::Enc.for('A128GCM')).to be_a JWE::Enc::A128gcm
    end

    it 'raises an error for a not-implemented enc' do
      expect { JWE::Enc.for('ERSA-4096-MAGIC') }.to raise_error(JWE::NotImplementedError)
    end
  end
end

gcm = [
  {
    class: JWE::Enc::A128gcm,
    keylen: 16,
    helloworld: "\"\xC6\xE4h\x8AI\x83\x90v\xAF\xE2\x11".force_encoding('BINARY'),
    tag: "\x85|\xF7\xE1\x94\tVG\x84\xE1\xA8\x81\a\xF4\xC60".force_encoding('BINARY'),
    ivlen: 12,
    iv: "\x0" * 12
  },
  {
    class: JWE::Enc::A192gcm,
    keylen: 24,
    helloworld: "\x9F\xA4\xEC\xCCa\x86\tRO\xD7\xE3\x8D".force_encoding('BINARY'),
    tag: "\xF6\xC0\xB8\x91A\xB1\xF0}\xD4u\xD0_\xCD\xA7\x17'".force_encoding('BINARY'),
    ivlen: 12,
    iv: "\x0" * 12
  },
  {
    class: JWE::Enc::A256gcm,
    keylen: 32,
    helloworld: "\xFDq\xDC\xDD\x87\x9DK\x97\x03G\x99\f".force_encoding('BINARY'),
    tag: "\xC6\xF1\r\xDD\x14\x7Fqf,6\x0EK\x7F\x9D\x1D\t".force_encoding('BINARY'),
    ivlen: 12,
    iv: "\x0" * 12
  },
  {
    class: JWE::Enc::A128cbcHs256,
    keylen: 32,
    helloworld: "\a\x02F\xA4m%\xDFH\xB4\xA4.\xBF:\xBF$\xE2".force_encoding('BINARY'),
    tag: "\xDE$t\xBA\x8B\xEE\u001Df\x81\a\xC1\xBB\x98\xDFl\xF2".force_encoding('BINARY'),
    ivlen: 16,
    iv: "\x0" * 16
  },
  {
    class: JWE::Enc::A192cbcHs384,
    keylen: 48,
    helloworld: "p\xFES\xF0\xB4\xCC]8\x1D\xDE\x8Dt\xE7tMh".force_encoding('BINARY'),
    tag: "\xA8a\x04kRJ\x06`tp6\x8E\x9Ba\xE1e\xF6\xDA\"\x15\xEBk\xFDm".force_encoding('BINARY'),
    ivlen: 16,
    iv: "\x0" * 16
  },
  {
    class: JWE::Enc::A256cbcHs512,
    keylen: 64,
    helloworld: "c\xFD\\\xB9Z\xB6\xE3\xB7\xEE\xA1\xD8\xDF\xB5\xB2\xF8\xEB".force_encoding('BINARY'),
    tag: "wC\xE3:\x91\x89W\x97\xBE\xB0\xBD\xEAo\xC66\x9F\xB82\xFDn\xA7.\u0014l\xFC2\xD7\xDFq\xB5[\xC6".force_encoding('BINARY'),
    ivlen: 16,
    iv: "\x0" * 16
  }
]

gcm.each do |group|
  describe group[:class] do
    let(:klass) { group[:class] }
    let(:key) { 'a' * group[:keylen] }
    let(:plaintext) { 'hello world!' }

    describe '#encrypt' do
      context 'when an invalid key is used' do
        it 'raises an error' do
          enc = klass.new('small')
          expect { enc.encrypt('plain', 'auth') }.to raise_error(JWE::BadCEK)
        end
      end

      context 'with a valid key' do
        it 'returns the encrypted payload' do
          enc = klass.new(key, group[:iv])
          expect(enc.encrypt(plaintext, '').force_encoding('BINARY')).to eq group[:helloworld]
        end

        it 'sets an authentication tag' do
          enc = klass.new(key, group[:iv])
          enc.encrypt(plaintext, '')
          expect(enc.tag).to eq group[:tag]
        end
      end
    end

    describe '#decrypt' do
      context 'when an invalid key is used' do
        it 'raises an error' do
          enc = klass.new('small')
          expect { enc.decrypt('plain', 'auth') }.to raise_error(JWE::BadCEK)
        end
      end

      context 'with a valid key' do
        context 'when a valid tag is authenticated' do
          it 'returns the plaintext' do
            enc = klass.new(key, group[:iv])
            enc.tag = group[:tag]
            expect(enc.decrypt(group[:helloworld], '')).to eq plaintext
          end
        end

        context 'when the tag is not valid' do
          it 'raises an error' do
            enc = klass.new(key, group[:iv])
            enc.tag = 'random'
            expect { enc.decrypt(group[:helloworld], '') }.to raise_error(JWE::InvalidData)
          end
        end

        context 'when the tag is not set' do
          it 'raises an error' do
            enc = klass.new(key, group[:iv])
            expect { enc.decrypt(group[:helloworld], '') }.to raise_error(JWE::InvalidData)
          end
        end

        context 'when the ciphertext is not valid' do
          it 'raises an error' do
            enc = klass.new(key, group[:iv])
            enc.tag = group[:tag]
            expect { enc.decrypt('random', '') }.to raise_error(JWE::InvalidData)
          end
        end
      end
    end

    describe '#cipher' do
      context 'when the cipher is not supported by the OpenSSL lib' do
        it 'raises an error' do
          enc = klass.new
          allow(enc).to receive(:cipher_name) { 'bad-cipher-128' }
          expect { enc.cipher }.to raise_error(JWE::NotImplementedError)
        end
      end

      context 'when the cipher is supported' do
        it 'returns the cipher object' do
          enc = klass.new
          allow(enc).to receive(:cipher_name) { OpenSSL::Cipher.ciphers.first }
          expect(enc.cipher).to be_an OpenSSL::Cipher
        end
      end
    end

    describe '#cek' do
      context 'when a key is not specified in initialization' do
        it "returns a randomly generated #{group[:keylen]}-bytes key" do
          expect(klass.new.cek.length).to eq group[:keylen]
        end
      end

      context 'when a cek is given' do
        it 'returns the cek' do
          expect(klass.new('cek').cek).to eq 'cek'
        end
      end
    end

    describe '#iv' do
      context 'when an iv is not specified in initialization' do
        it "returns a randomly generated #{group[:ivlen]}-bytes iv" do
          expect(klass.new.iv.length).to eq group[:ivlen]
        end
      end

      context 'when a iv is given' do
        it 'returns the iv' do
          expect(klass.new('cek', 'iv').iv).to eq 'iv'
        end
      end
    end

    describe '.available?' do
      context 'when the cipher is not available' do
        it 'is false' do
          allow_any_instance_of(klass).to receive(:cipher) { raise JWE::NotImplementedError.new }
          expect(klass.available?).to be_falsey
        end
      end

      context 'when the cipher is available' do
        it 'is true' do
          allow_any_instance_of(klass).to receive(:cipher)
          expect(klass.available?).to be_truthy
        end
      end
    end

    describe 'full roundtrip' do
      it 'decrypts the ciphertext to the original plaintext' do
        enc = klass.new
        ciphertext = enc.encrypt(plaintext, '')
        expect(enc.decrypt(ciphertext, '')).to eq plaintext
      end
    end
  end
end
