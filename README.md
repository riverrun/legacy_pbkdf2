# LegacyPbkdf2

An example of using Comeonin version 5 with Plug.Crypto's Pbkdf2 implementation.

This example provides a **legacy** implementation of the Pbkdf2 password hashing
algorithm, using Comeonin and Plug.Crypto. It was written in response to
[this issue](https://github.com/riverrun/pbkdf2_elixir/pull/3), where an
old system needed to be supported.

LegacyPbkdf2 is not recommended for modern password hashing.
For information about current recommendations, see
[Choosing a library](https://github.com/riverrun/comeonin/wiki/Choosing-the-password-hashing-library).
