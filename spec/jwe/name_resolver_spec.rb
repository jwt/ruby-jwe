# frozen_string_literal: true

require 'jwe/name_resolver'

module JWE
  describe NameResolver do
    def test_class
      Class.new do
        include JWE::NameResolver
      end
    end

    describe '#param_to_class_name' do
      it 'converts params to class names' do
        conversions = {
          'dir' => 'Dir',
          'RSA-OAEP' => 'RsaOaep',
          'RSA-OAEP-256' => 'RsaOaep256',
          'ECDH-ES+A128KW' => 'EcdhEsA128kw',
          'A128KW' => 'A128kw',
          'A192KW' => 'A192kw',
          'A256KW' => 'A256kw',
          'A128GCMKW' => 'A128gcmkw',
          'A192GCMKW' => 'A192gcmkw',
          'A256GCMKW' => 'A256gcmkw',
          'A128GCM' => 'A128gcm',
          'A256GCM' => 'A256gcm',
          'A128CBC-HS256' => 'A128cbcHs256',
          'A256CBC-HS512' => 'A256cbcHs512'
        }
        conversions.each do |param, class_name|
          expect(test_class.new.param_to_class_name(param)).to eq class_name
        end
      end
    end

    describe '#class_name_to_param' do
      it 'converts class names to params' do
        conversions = {
          'JWE::Alg::Dir' => 'DIR',
          'JWE::Alg::RsaOaep' => 'RSA-OAEP',
          'JWE::Alg::RsaOaep256' => 'RSA-OAEP256',
          'JWE::Alg::A128kw' => 'A128KW',
          'JWE::Alg::A128gcmkw' => 'A128GCMKW',
          'JWE::Enc::A128gcm' => 'A128GCM',
          'JWE::Enc::A128cbcHs256' => 'A128CBC-HS256'
        }
        conversions.each do |full_class_name, param|
          stub_const(full_class_name, test_class)
          instance = Object.const_get(full_class_name).new
          expect(instance.class_name_to_param).to eq param
        end
      end
    end

    describe 'roundtrip conversions' do
      it 'converts param to class name and back' do
        params = {
          'RSA-OAEP' => 'RSA-OAEP',
          'A128KW' => 'A128KW',
          'A128GCMKW' => 'A128GCMKW',
          'dir' => 'DIR'
        }
        params.each do |param, expected|
          class_name = test_class.new.param_to_class_name(param)
          stub_const("JWE::Alg::#{class_name}", test_class)
          instance = Object.const_get("JWE::Alg::#{class_name}").new
          expect(instance.class_name_to_param).to eq expected
        end
      end
    end
  end
end
