# frozen_string_literal: true

module JWE
  # Converts between JWE parameter names and Ruby class names
  module NameResolver
    def param_to_class_name(param)
      klass = param.gsub(/[-+]/, '_').downcase.sub(/^[a-z\d]*/) { ::Regexp.last_match(0).capitalize }
      klass.gsub(/_([a-z\d]*)/i) { Regexp.last_match(1).capitalize }
    end

    def class_name_to_param
      klass = self.class.name.split('::').last

      klass.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
           .gsub(/([a-z\d])([A-Z])/, '\1_\2')
           .gsub('_', '-')
           .upcase
    end
  end
end
