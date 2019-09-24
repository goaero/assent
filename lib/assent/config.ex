defmodule Assent.Config do
  @moduledoc """
  Methods to handle configurations.
  """

  defmodule MissingKeyError do
    defexception [:message]
  end

  @type t :: Keyword.t()

  @doc false
  @spec fetch(t(), atom()) :: {:ok, any()} | {:error, %MissingKeyError{}}
  def fetch(config, key) do
    case Keyword.fetch(config, key) do
      {:ok, value} -> {:ok, value}
      :error       -> {:error, MissingKeyError.exception("Key `:#{key}` not found in config")}
    end
  end

  @doc false
  defdelegate get(config, key, default), to: Keyword

  @doc false
  defdelegate put(config, key, value), to: Keyword

  @doc false
  defdelegate merge(config_a, config_b), to: Keyword
end
