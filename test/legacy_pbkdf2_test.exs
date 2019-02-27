defmodule LegacyPbkdf2Test do
  use ExUnit.Case

  import Comeonin.BehaviourTestHelper

  test "implementation of Comeonin.PasswordHash behaviour" do
    password = Enum.random(ascii_passwords())
    assert correct_password_true(LegacyPbkdf2, password)
    assert wrong_password_false(LegacyPbkdf2, password)
  end

  test "Comeonin.PasswordHash behaviour with non-ascii characters" do
    password = Enum.random(non_ascii_passwords())
    assert correct_password_true(LegacyPbkdf2, password)
    assert wrong_password_false(LegacyPbkdf2, password)
  end

  test "add_hash function" do
    password = Enum.random(ascii_passwords())
    assert add_hash_creates_map(LegacyPbkdf2, password)
  end

  test "check_pass function" do
    password = Enum.random(ascii_passwords())
    assert check_pass_returns_user(LegacyPbkdf2, password)
    assert check_pass_returns_error(LegacyPbkdf2, password)
    assert check_pass_nil_user(LegacyPbkdf2)
  end

  test "hashes with different lengths are correctly verified" do
    hash = LegacyPbkdf2.hash_pwd_salt("password", length: 128)
    assert LegacyPbkdf2.verify_pass("password", hash) == true
  end

  test "hashes with different number of rounds are correctly verified" do
    hash = LegacyPbkdf2.hash_pwd_salt("password", iterations: 10000)
    assert LegacyPbkdf2.verify_pass("password", hash) == true
  end

  test "add_hash with a custom hash_key and check_pass" do
    assert {:ok, user} =
             LegacyPbkdf2.add_hash("password", hash_key: :encrypted_password)
             |> LegacyPbkdf2.check_pass("password")

    assert {:error, "invalid password"} =
             LegacyPbkdf2.add_hash("pass", hash_key: :encrypted_password)
             |> LegacyPbkdf2.check_pass("password")

    assert Map.has_key?(user, :encrypted_password)
  end

  test "check_pass with custom hash_key" do
    assert {:ok, user} =
             LegacyPbkdf2.add_hash("password", hash_key: :custom_hash)
             |> LegacyPbkdf2.check_pass("password", hash_key: :custom_hash)

    assert Map.has_key?(user, :custom_hash)
  end

  test "check_pass with invalid hash_key" do
    {:error, message} =
      LegacyPbkdf2.add_hash("password", hash_key: :unconventional_name)
      |> LegacyPbkdf2.check_pass("password")

    assert message =~ "no password hash found"
  end
end
