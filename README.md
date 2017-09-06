# JWE

[![Build Status](https://travis-ci.org/jwt/ruby-jwe.svg)](https://travis-ci.org/jwt/ruby-jwe)
[![Code Climate](https://codeclimate.com/github/aomega08/jwe/badges/gpa.svg)](https://codeclimate.com/github/aomega08/jwe)
[![Test Coverage](https://codeclimate.com/github/aomega08/jwe/badges/coverage.svg)](https://codeclimate.com/github/aomega08/jwe/coverage)

A ruby implementation of the [RFC 7516 JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516) standard.

## Installing

```bash
gem install jwe
```
## Usage

This example uses the default alg and enc methods (RSA-OAEP and A128CBC-HS256). It requires an RSA key.

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key)
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses a custom enc method:

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, enc: 'A192GCM')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses the 'dir' alg method. It requires an encryption key of the correct size for the enc method

```ruby
require 'jwe'

key = SecureRandom.random_bytes(32)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, alg: 'dir')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example uses the DEFLATE algorithm on the plaintext to reduce the result size.

```ruby
require 'jwe'

key = OpenSSL::PKey::RSA.generate(2048)
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, key, zip: 'DEF')
puts encrypted

plaintext = JWE.decrypt(encrypted, key)
puts plaintext #"The quick brown fox jumps over the lazy dog."
```

This example sets an extra header.

```ruby
require 'jwe'

keys = {
  'id-1' => OpenSSL::PKey::RSA.generate(2048)
}
payload = "The quick brown fox jumps over the lazy dog."

encrypted = JWE.encrypt(payload, keys['id-1'], headers: {kid: 'id-1'})
puts encrypted
```

## Available Algorithms

The RFC 7518 JSON Web Algorithms (JWA) spec defines the algorithms for [encryption](https://tools.ietf.org/html/rfc7518#section-5.1)
 and [key management](https://tools.ietf.org/html/rfc7518#section-4.1) to be supported by a JWE implementation.

Only a subset of these algorithms is implemented in this gem. Striked elements are not available:

Key management:
* RSA1_5
* RSA-OAEP (default)
* ~~RSA-OAEP-256~~
* A128KW
* A192KW
* A256KW
* dir
* ~~ECDH-ES~~
* ~~ECDH-ES+A128KW~~
* ~~ECDH-ES+A192KW~~
* ~~ECDH-ES+A256KW~~
* ~~A128GCMKW~~
* ~~A192GCMKW~~
* ~~A256GCMKW~~
* ~~PBES2-HS256+A128KW~~
* ~~PBES2-HS384+A192KW~~
* ~~PBES2-HS512+A256KW~~

Encryption:
* A128CBC-HS256 (default)
* A192CBC-HS384
* A256CBC-HS512
* A128GCM
* A192GCM
* A256GCM

## License

The MIT License

* Copyright © 2016 Francesco Boffa

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

