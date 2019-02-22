ExUnit.start()

defmodule LegacyPbkdf2TestHelper do
  use ExUnit.Case

  def password_hash_check(password, wrong_list) do
    hash = LegacyPbkdf2.hash_pwd_salt(password)
    assert LegacyPbkdf2.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute LegacyPbkdf2.verify_pass(wrong, hash)
    end
  end

  def add_hash_check(password, wrong_list) do
    %{password_hash: hash, password: nil} = LegacyPbkdf2.add_hash(password)
    assert LegacyPbkdf2.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute LegacyPbkdf2.verify_pass(wrong, hash)
    end
  end

  def check_pass_check(password, wrong_list) do
    hash = LegacyPbkdf2.hash_pwd_salt(password)
    user = %{id: 2, name: "fred", password_hash: hash}
    assert LegacyPbkdf2.check_pass(user, password) == {:ok, user}
    assert LegacyPbkdf2.check_pass(nil, password) == {:error, "invalid user-identifier"}

    for wrong <- wrong_list do
      assert LegacyPbkdf2.check_pass(user, wrong) == {:error, "invalid password"}
    end
  end
end
