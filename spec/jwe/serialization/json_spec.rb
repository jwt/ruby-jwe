# frozen_string_literal: true

require 'spec_helper'

RSpec.describe JWE::Serialization::Json do
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:plaintext) { 'Hello, World!' }

  describe JWE::Serialization::Json::General do
    describe '.encode' do
      it 'creates valid JSON structure' do
        result = described_class.encode(
          protected_header: 'eyJlbmMiOiJBMTI4R0NNIn0',
          unprotected_header: { 'jku' => 'https://example.com' },
          recipients: [{ header: { 'alg' => 'RSA-OAEP' }, encrypted_key: 'encrypted' }],
          iv: 'iv_value',
          ciphertext: 'ciphertext',
          tag: 'tag_value',
          aad: nil
        )

        json = JSON.parse(result)
        expect(json).to have_key('protected')
        expect(json).to have_key('unprotected')
        expect(json).to have_key('recipients')
        expect(json).to have_key('iv')
        expect(json).to have_key('ciphertext')
        expect(json).to have_key('tag')
        expect(json).not_to have_key('aad')
      end

      it 'omits empty optional fields' do
        result = described_class.encode(
          protected_header: 'eyJlbmMiOiJBMTI4R0NNIn0',
          unprotected_header: nil,
          recipients: [{ header: nil, encrypted_key: 'encrypted' }],
          iv: 'iv_value',
          ciphertext: 'ciphertext',
          tag: 'tag_value',
          aad: nil
        )

        json = JSON.parse(result)
        expect(json).not_to have_key('unprotected')
      end

      it 'includes aad when provided' do
        result = described_class.encode(
          protected_header: 'eyJlbmMiOiJBMTI4R0NNIn0',
          unprotected_header: nil,
          recipients: [{ header: nil, encrypted_key: 'encrypted' }],
          iv: 'iv_value',
          ciphertext: 'ciphertext',
          tag: 'tag_value',
          aad: 'additional data'
        )

        json = JSON.parse(result)
        expect(json).to have_key('aad')
      end
    end

    describe '.decode' do
      it 'parses valid JSON' do
        json = {
          'protected' => 'eyJlbmMiOiJBMTI4R0NNIn0',
          'recipients' => [{ 'header' => { 'alg' => 'RSA-OAEP' }, 'encrypted_key' => 'ZW5jcnlwdGVk' }],
          'iv' => 'aXY',
          'ciphertext' => 'Y2lwaGVydGV4dA',
          'tag' => 'dGFn'
        }.to_json

        result = described_class.decode(JSON.parse(json))
        expect(result[:protected_header]).to eq('eyJlbmMiOiJBMTI4R0NNIn0')
        expect(result[:recipients].length).to eq(1)
      end

      it 'raises error for missing recipients' do
        json = { 'ciphertext' => 'Y2lwaGVydGV4dA' }.to_json
        expect do
          described_class.decode(JSON.parse(json))
        end.to raise_error(JWE::DecodeError, /Missing recipients/)
      end

      it 'raises error for missing ciphertext' do
        json = { 'recipients' => [] }.to_json
        expect do
          described_class.decode(JSON.parse(json))
        end.to raise_error(JWE::DecodeError, /Missing ciphertext/)
      end
    end
  end

  describe JWE::Serialization::Json::Flattened do
    describe '.encode' do
      it 'creates valid JSON structure' do
        result = described_class.encode(
          protected_header: 'eyJlbmMiOiJBMTI4R0NNIn0',
          unprotected_header: nil,
          header: { 'alg' => 'RSA-OAEP' },
          encrypted_key: 'encrypted',
          iv: 'iv_value',
          ciphertext: 'ciphertext',
          tag: 'tag_value',
          aad: nil
        )

        json = JSON.parse(result)
        expect(json).to have_key('protected')
        expect(json).to have_key('header')
        expect(json).to have_key('encrypted_key')
        expect(json).not_to have_key('recipients')
      end

      it 'omits empty optional fields' do
        result = described_class.encode(
          protected_header: 'eyJlbmMiOiJBMTI4R0NNIn0',
          unprotected_header: nil,
          header: nil,
          encrypted_key: 'encrypted',
          iv: 'iv_value',
          ciphertext: 'ciphertext',
          tag: 'tag_value',
          aad: nil
        )

        json = JSON.parse(result)
        expect(json).not_to have_key('header')
        expect(json).not_to have_key('unprotected')
      end
    end

    describe '.decode' do
      it 'parses valid JSON' do
        json = {
          'protected' => 'eyJlbmMiOiJBMTI4R0NNIn0',
          'header' => { 'alg' => 'RSA-OAEP' },
          'encrypted_key' => 'ZW5jcnlwdGVk',
          'iv' => 'aXY',
          'ciphertext' => 'Y2lwaGVydGV4dA',
          'tag' => 'dGFn'
        }.to_json

        result = described_class.decode(JSON.parse(json))
        expect(result[:recipients].length).to eq(1)
        expect(result[:recipients][0][:header]).to eq({ 'alg' => 'RSA-OAEP' })
      end

      it 'raises error if recipients is present' do
        json = {
          'recipients' => [],
          'ciphertext' => 'Y2lwaGVydGV4dA'
        }.to_json
        expect do
          described_class.decode(JSON.parse(json))
        end.to raise_error(JWE::DecodeError, /cannot have recipients/)
      end

      it 'raises error for missing ciphertext' do
        json = { 'header' => { 'alg' => 'RSA-OAEP' } }.to_json
        expect do
          described_class.decode(JSON.parse(json))
        end.to raise_error(JWE::DecodeError, /Missing ciphertext/)
      end
    end
  end
end

RSpec.describe 'JWE JSON Serialization' do
  let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:plaintext) { 'Hello, World!' }

  describe 'JWE.encrypt_json' do
    context 'with General serialization' do
      it 'encrypts with a single recipient' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        json = JSON.parse(encrypted)
        expect(json).to have_key('protected')
        expect(json).to have_key('recipients')
        expect(json['recipients'].length).to eq(1)
      end

      it 'encrypts with multiple recipients' do
        rsa_key2 = OpenSSL::PKey::RSA.generate(2048)
        recipients = [
          JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' }),
          JWE::Recipient.new(key: rsa_key2.public_key, header: { 'alg' => 'RSA-OAEP' })
        ]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        json = JSON.parse(encrypted)
        expect(json['recipients'].length).to eq(2)
      end

      it 'includes unprotected header when provided' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     unprotected_header: { 'jku' => 'https://example.com' })

        json = JSON.parse(encrypted)
        expect(json['unprotected']).to eq({ 'jku' => 'https://example.com' })
      end
    end

    context 'with Flattened serialization' do
      it 'encrypts with a single recipient' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     format: :flattened)

        json = JSON.parse(encrypted)
        expect(json).to have_key('protected')
        expect(json).to have_key('encrypted_key')
        expect(json).not_to have_key('recipients')
      end

      it 'raises error for multiple recipients' do
        rsa_key2 = OpenSSL::PKey::RSA.generate(2048)
        recipients = [
          JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' }),
          JWE::Recipient.new(key: rsa_key2.public_key, header: { 'alg' => 'RSA-OAEP' })
        ]

        expect do
          JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' }, format: :flattened)
        end.to raise_error(ArgumentError, /only one recipient/)
      end
    end

    context 'with AAD' do
      it 'includes AAD in encryption' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     aad: 'my additional data')

        json = JSON.parse(encrypted)
        expect(json).to have_key('aad')
      end
    end

    context 'with invalid parameters' do
      it 'raises error for empty recipients' do
        expect do
          JWE.encrypt_json(plaintext, [], protected_header: { enc: 'A128GCM' })
        end.to raise_error(ArgumentError, /At least one recipient/)
      end

      it 'raises error for missing enc' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        expect do
          JWE.encrypt_json(plaintext, recipients, protected_header: {})
        end.to raise_error(ArgumentError, /enc is required/)
      end

      it 'raises error for missing alg in recipient' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: {})]
        expect do
          JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })
        end.to raise_error(ArgumentError, /alg is required/)
      end
    end
  end

  describe 'JWE.decrypt_json' do
    context 'with General serialization' do
      it 'decrypts successfully' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        result = JWE.decrypt_json(encrypted, rsa_key)
        expect(result.plaintext).to eq(plaintext)
        expect(result.successful_recipients).to eq([0])
      end

      it 'decrypts with multiple recipients using correct key' do
        rsa_key2 = OpenSSL::PKey::RSA.generate(2048)
        recipients = [
          JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' }),
          JWE::Recipient.new(key: rsa_key2.public_key, header: { 'alg' => 'RSA-OAEP' })
        ]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        result = JWE.decrypt_json(encrypted, rsa_key2)
        expect(result.plaintext).to eq(plaintext)
      end
    end

    context 'with Flattened serialization' do
      it 'decrypts successfully' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     format: :flattened)

        result = JWE.decrypt_json(encrypted, rsa_key)
        expect(result.plaintext).to eq(plaintext)
      end
    end

    context 'with multiple keys' do
      it 'selects the correct key by kid' do
        rsa_key2 = OpenSSL::PKey::RSA.generate(2048)
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP', 'kid' => 'my-key' })]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        keys = { 'my-key' => rsa_key, 'other-key' => rsa_key2 }
        result = JWE.decrypt_json(encrypted, keys)
        expect(result.plaintext).to eq(plaintext)
      end
    end

    context 'with invalid data' do
      it 'raises error when no recipient can decrypt' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients, protected_header: { enc: 'A128GCM' })

        wrong_key = OpenSSL::PKey::RSA.generate(2048)
        expect do
          JWE.decrypt_json(encrypted, wrong_key)
        end.to raise_error(JWE::InvalidData, /No recipient could decrypt/)
      end
    end

    context 'with AAD' do
      it 'validates AAD during decryption' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     aad: 'my additional data')

        result = JWE.decrypt_json(encrypted, rsa_key)
        expect(result.plaintext).to eq(plaintext)
      end

      it 'fails if AAD is tampered' do
        recipients = [JWE::Recipient.new(key: rsa_key.public_key, header: { 'alg' => 'RSA-OAEP' })]
        encrypted = JWE.encrypt_json(plaintext, recipients,
                                     protected_header: { enc: 'A128GCM' },
                                     aad: 'my additional data')

        json = JSON.parse(encrypted)
        json['aad'] = JWE::Base64.jwe_encode('tampered data')
        tampered = json.to_json

        expect do
          JWE.decrypt_json(tampered, rsa_key)
        end.to raise_error(JWE::InvalidData)
      end
    end
  end
end

RSpec.describe JWE::Recipient do
  it 'creates with key only' do
    key = OpenSSL::PKey::RSA.generate(2048)
    recipient = described_class.new(key: key)
    expect(recipient.key).to eq(key)
    expect(recipient.header).to eq({})
  end

  it 'creates with key and header' do
    key = OpenSSL::PKey::RSA.generate(2048)
    recipient = described_class.new(key: key, header: { 'alg' => 'RSA-OAEP' })
    expect(recipient.key).to eq(key)
    expect(recipient.header).to eq({ 'alg' => 'RSA-OAEP' })
  end
end

RSpec.describe JWE::DecryptionResult do
  it 'creates with all fields' do
    result = described_class.new(plaintext: 'test', successful_recipients: [0], failed_recipients: [1])
    expect(result.plaintext).to eq('test')
    expect(result.successful_recipients).to eq([0])
    expect(result.failed_recipients).to eq([1])
  end

  it 'has default empty arrays' do
    result = described_class.new(plaintext: 'test')
    expect(result.successful_recipients).to eq([])
    expect(result.failed_recipients).to eq([])
  end
end
