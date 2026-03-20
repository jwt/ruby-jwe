# frozen_string_literal: true

module JWE
  module Serialization
    # JSON Serialization namespace (RFC 7516 Section 7.2)
    module Json
      # General JWE JSON Serialization (RFC 7516 Section 7.2.1)
      # Supports multiple recipients
      class General
        class << self
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Metrics/ParameterLists
          def encode(protected_header:, unprotected_header:, recipients:, iv:, ciphertext:, tag:, aad:)
            result = {}

            result['protected'] = protected_header if protected_header && !protected_header.empty?
            result['unprotected'] = unprotected_header if unprotected_header && !unprotected_header.empty?

            result['recipients'] = recipients.map do |r|
              recipient = {}
              recipient['header'] = r[:header] if r[:header] && !r[:header].empty?
              recipient['encrypted_key'] = Base64.jwe_encode(r[:encrypted_key])
              recipient
            end

            result['aad'] = Base64.jwe_encode(aad) if aad
            result['iv'] = Base64.jwe_encode(iv)
            result['ciphertext'] = Base64.jwe_encode(ciphertext)
            result['tag'] = Base64.jwe_encode(tag)

            result.to_json
          end

          def decode(data)
            raise JWE::DecodeError, 'Missing recipients' unless data['recipients']
            raise JWE::DecodeError, 'Missing ciphertext' unless data['ciphertext']

            {
              protected_header: data['protected'],
              unprotected_header: data['unprotected'],
              recipients: data['recipients'].map do |r|
                {
                  header: r['header'],
                  encrypted_key: Base64.jwe_decode(r['encrypted_key'] || '')
                }
              end,
              iv: Base64.jwe_decode(data['iv'] || ''),
              ciphertext: Base64.jwe_decode(data['ciphertext']),
              tag: Base64.jwe_decode(data['tag'] || ''),
              aad: data['aad'] ? Base64.jwe_decode(data['aad']) : nil
            }
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity, Metrics/ParameterLists
        end
      end

      # Flattened JWE JSON Serialization (RFC 7516 Section 7.2.2)
      # Single recipient only
      class Flattened
        class << self
          # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ParameterLists
          def encode(protected_header:, unprotected_header:, header:, encrypted_key:, iv:, ciphertext:, tag:, aad:)
            result = {}

            result['protected'] = protected_header if protected_header && !protected_header.empty?
            result['unprotected'] = unprotected_header if unprotected_header && !unprotected_header.empty?
            result['header'] = header if header && !header.empty?
            result['encrypted_key'] = Base64.jwe_encode(encrypted_key)
            result['aad'] = Base64.jwe_encode(aad) if aad
            result['iv'] = Base64.jwe_encode(iv)
            result['ciphertext'] = Base64.jwe_encode(ciphertext)
            result['tag'] = Base64.jwe_encode(tag)

            result.to_json
          end

          def decode(data)
            raise JWE::DecodeError, 'Missing ciphertext' unless data['ciphertext']
            raise JWE::DecodeError, 'Flattened format cannot have recipients' if data['recipients']

            {
              protected_header: data['protected'],
              unprotected_header: data['unprotected'],
              recipients: [
                {
                  header: data['header'],
                  encrypted_key: Base64.jwe_decode(data['encrypted_key'] || '')
                }
              ],
              iv: Base64.jwe_decode(data['iv'] || ''),
              ciphertext: Base64.jwe_decode(data['ciphertext']),
              tag: Base64.jwe_decode(data['tag'] || ''),
              aad: data['aad'] ? Base64.jwe_decode(data['aad']) : nil
            }
          end
          # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/ParameterLists
        end
      end
    end
  end
end
