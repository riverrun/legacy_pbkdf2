defmodule LegacyPbkdf2 do
  @moduledoc """
  Documentation for LegacyPbkdf2.
  """

  use Comeonin

  alias Plug.Crypto.KeyGenerator

  @doc """
  Generate a random salt.
  """
  def gen_salt(length) when length in 4..1024 do
    :crypto.strong_rand_bytes(length)
  end

  @impl true
  def hash_pwd_salt(password, opts \\ []) do
    salt = gen_salt(opts[:salt_len] || 4)
    digest = opts[:digest] || :sha
    iterations = opts[:iterations] || 4096
    length = opts[:length] || 16

    password
    |> KeyGenerator.generate(salt, digest: digest, iterations: iterations, length: length)
    |> format(salt, digest, iterations)
  end

  @impl true
  def verify_pass(password, stored_hash) do
    with {hash, salt, opts} <- unformat(stored_hash),
         do:
           password
           |> KeyGenerator.generate(salt, opts)
           |> Plug.Crypto.secure_compare(hash)
  end

  defp format(hash, salt, digest, iterations) do
    "$pbkdf2-#{digest}$#{iterations}$#{Base.encode64(salt)}$#{Base.encode64(hash)}"
  end

  defp unformat("$pbkdf2-" <> formatted_hash) do
    [digest, iterations, salt, hash] = String.split(formatted_hash, "$")
    hash = Base.decode64!(hash)

    {
      hash,
      Base.decode64!(salt),
      [
        digest: String.to_atom(digest),
        iterations: String.to_integer(iterations),
        length: byte_size(hash)
      ]
    }
  end
end
