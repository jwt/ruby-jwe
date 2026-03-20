# frozen_string_literal: true

require 'jwe/validator'

module JWE
  describe Validator do
    describe '#check_params' do
      it 'accepts valid algorithm parameters' do
        valid_algs = %w[RSA1_5 RSA-OAEP RSA-OAEP-256 A128KW A192KW A256KW
                        A128GCMKW A192GCMKW A256GCMKW dir]
        valid_algs.each do |alg|
          expect { Validator.new.check_params(alg, 'A128GCM', nil, 'key') }.not_to raise_error
        end
      end

      it 'accepts valid encryption parameters' do
        valid_encs = %w[A128CBC-HS256 A192CBC-HS384 A256CBC-HS512
                        A128GCM A192GCM A256GCM]
        valid_encs.each do |enc|
          expect { Validator.new.check_params('RSA-OAEP', enc, nil, 'key') }.not_to raise_error
        end
      end

      it 'accepts valid compression parameters' do
        valid_zips = ['DEF', nil, '']
        valid_zips.each do |zip|
          expect { Validator.new.check_params('RSA-OAEP', 'A128GCM', zip, 'key') }.not_to raise_error
        end
      end

      it 'accepts valid keys' do
        valid_keys = ['valid_key', OpenSSL::PKey::RSA.new(2048)]
        valid_keys.each do |key|
          expect { Validator.new.check_params('RSA-OAEP', 'A128GCM', nil, key) }.not_to raise_error
        end
      end

      it 'raises error for invalid algorithm' do
        expect { Validator.new.check_params('INVALID', 'A128GCM', nil, 'key') }
          .to raise_error(ArgumentError, /"INVALID" is not a valid alg method/)
      end

      it 'raises error for invalid encryption' do
        expect { Validator.new.check_params('RSA-OAEP', 'INVALID', nil, 'key') }
          .to raise_error(ArgumentError, /"INVALID" is not a valid enc method/)
      end

      it 'raises error for invalid compression' do
        expect { Validator.new.check_params('RSA-OAEP', 'A128GCM', 'GZIP', 'key') }
          .to raise_error(ArgumentError, /"GZIP" is not a valid zip method/)
      end

      it 'raises error for invalid keys' do
        invalid_keys = [nil, '', '   ']
        invalid_keys.each do |key|
          expect { Validator.new.check_params('RSA-OAEP', 'A128GCM', nil, key) }
            .to raise_error(ArgumentError, /must not be nil or blank/)
        end
      end
    end
  end
end
