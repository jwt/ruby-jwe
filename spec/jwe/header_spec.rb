# frozen_string_literal: true

require 'jwe/header'
require 'jwe/alg'
require 'jwe/enc'
require 'jwe/alg/a128gcmkw'
require 'jwe/alg/a192gcmkw'
require 'jwe/alg/a256gcmkw'

module JWE
  describe Header do
    describe '#generate_header' do
      it 'generates basic header with alg and enc' do
        alg_cipher = Alg.for('RSA-OAEP').new(OpenSSL::PKey::RSA.new(2048))
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, {})
        header = JSON.parse(header_json)

        expect(header['alg']).to eq 'RSA-OAEP'
        expect(header['enc']).to eq 'A128GCM'
      end

      it 'includes zip parameter when provided' do
        alg_cipher = Alg.for('A128KW').new(SecureRandom.random_bytes(16))
        enc_cipher = Enc.for('A256GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, 'DEF', {})
        header = JSON.parse(header_json)

        expect(header['alg']).to eq 'A128KW'
        expect(header['enc']).to eq 'A256GCM'
        expect(header['zip']).to eq 'DEF'
      end

      it 'excludes zip parameter when nil' do
        alg_cipher = Alg.for('A128KW').new(SecureRandom.random_bytes(16))
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, {})
        header = JSON.parse(header_json)

        expect(header).not_to have_key('zip')
      end

      it 'includes additional header parameters from algorithm' do
        alg_cipher = Alg.for('A128GCMKW').new(SecureRandom.random_bytes(16))
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, {})
        header = JSON.parse(header_json)

        expect(header['alg']).to eq 'A128GCMKW'
        expect(header['enc']).to eq 'A128GCM'
        expect(header).to have_key('iv')
        expect(header).to have_key('tag')
      end

      it 'does not include additional parameters when algorithm does not need them' do
        alg_cipher = Alg.for('RSA-OAEP').new(OpenSSL::PKey::RSA.new(2048))
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, {})
        header = JSON.parse(header_json)

        expect(header.keys).to contain_exactly('alg', 'enc')
      end

      it 'includes custom additional header parameters' do
        alg_cipher = Alg.for('RSA-OAEP').new(OpenSSL::PKey::RSA.new(2048))
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, { custom: 'value', foo: 'bar' })
        header = JSON.parse(header_json)

        expect(header['alg']).to eq 'RSA-OAEP'
        expect(header['enc']).to eq 'A128GCM'
        expect(header['custom']).to eq 'value'
        expect(header['foo']).to eq 'bar'
      end

      it 'combines all parameters correctly' do
        alg_cipher = Alg.for('A256GCMKW').new(SecureRandom.random_bytes(32))
        enc_cipher = Enc.for('A256GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, 'DEF', { copyright: 'MIT' })
        header = JSON.parse(header_json)

        expect(header['alg']).to eq 'A256GCMKW'
        expect(header['enc']).to eq 'A256GCM'
        expect(header['zip']).to eq 'DEF'
        expect(header).to have_key('iv')
        expect(header).to have_key('tag')
        expect(header['copyright']).to eq 'MIT'
      end

      it 'returns valid JSON string' do
        alg_cipher = Alg.for('dir').new('test_key')
        enc_cipher = Enc.for('A128GCM')

        header_json = Header.new.generate_header(alg_cipher, enc_cipher, nil, {})

        expect { JSON.parse(header_json) }.not_to raise_error
        expect(header_json).to be_a(String)
      end
    end
  end
end
