# frozen_string_literal: true

require 'spec_helper'

describe JWE do
  describe '.check_crit' do
    context 'when crit header is not present' do
      it 'does not raise an error' do
        header = { alg: 'RSA-OAEP', enc: 'A128GCM' }
        expect { JWE.check_crit(header) }.not_to raise_error
      end
    end

    context 'when crit header is present' do
      context 'with valid critical headers' do
        before do
          JWE.supported_critical_headers = ['custom-header']
        end

        after do
          JWE.supported_critical_headers = []
        end

        it 'accepts supported critical headers that exist in the header' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: ['custom-header'], 'custom-header' => 'value' }
          expect { JWE.check_crit(header) }.not_to raise_error
        end
      end

      context 'with invalid critical headers' do
        it 'raises an error when crit is not an array' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: 'not-an-array' }
          expect { JWE.check_crit(header) }.to raise_error(ArgumentError, /"crit" header must be a non-empty array/)
        end

        it 'raises an error when crit is an empty array' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: [] }
          expect { JWE.check_crit(header) }.to raise_error(ArgumentError, /"crit" header must be a non-empty array/)
        end

        it 'raises an error when crit contains a registered header' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: ['alg'] }
          expect { JWE.check_crit(header) }.to raise_error(ArgumentError, /registered header/)
        end

        it 'raises an error when crit references a non-existent header' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: ['missing-header'] }
          expect { JWE.check_crit(header) }.to raise_error(ArgumentError, /not present in header/)
        end

        it 'raises an error when crit contains an unsupported header' do
          header = { alg: 'RSA-OAEP', enc: 'A128GCM', crit: ['unsupported'], 'unsupported' => 'value' }
          expect { JWE.check_crit(header) }.to raise_error(JWE::InvalidData, /Unsupported critical header/)
        end
      end
    end
  end

  describe 'encryption/decryption with crit header' do
    let(:key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:plaintext) { 'Hello, World!' }

    context 'with supported critical headers' do
      before do
        JWE.supported_critical_headers = ['custom-header']
      end

      after do
        JWE.supported_critical_headers = []
      end

      it 'successfully encrypts and decrypts with crit header' do
        encrypted = JWE.encrypt(plaintext, key, crit: ['custom-header'], 'custom-header': 'value')
        decrypted = JWE.decrypt(encrypted, key)
        expect(decrypted).to eq(plaintext)
      end
    end
  end
end
