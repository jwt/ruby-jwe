# frozen_string_literal: true

module JWE
  # Generates JWE header from algorithm, encryption, and compression parameters
  class Header
    def generate_header(alg_cipher, enc_cipher, zip, additional_header_parameters)
      header_parameters = {
        alg: alg_cipher.class_name_to_param,
        enc: enc_cipher.class_name_to_param
      }

      header_parameters.merge!(zip: zip) if zip

      header_parameters.merge!(alg_cipher.header_parameters) if alg_cipher.need_additional_header_parameters?

      header_parameters.merge(additional_header_parameters).to_json
    end
  end
end
