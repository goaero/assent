defmodule Assent.Strategy do
  @moduledoc """
  Used for creating strategies.

  ## Usage

  Set up `my_strategy.ex` the following way:

      defmodule MyStrategy do
        @behaviour Assent.Strategy

        alias Assent.Strategy, as: Helpers

        def authorize_url(config) do
          # Generate redirect URL

          {:ok, %{url: url, ...}}
        end

        def callback(config, params) do
          # Fetch user data

          user = Helpers.normalize_userinfo(userinfo)

          {:ok, %{user: user, ...}}
        end
      end
  """
  alias Assent.{Config, HTTPResponse, RequestError}

  @callback authorize_url(Config.t()) :: {:ok, %{:url => binary(), optional(atom()) => any()}} | {:error, term()}
  @callback callback(Config.t(), map()) :: {:ok, %{:user => map(), optional(atom()) => any()}} | {:error, term()}

  @doc """
  Makes a HTTP request.
  """
  @spec request(atom(), binary(), binary() | nil, list(), Config.t()) :: {:ok, HTTPResponse.t()} | {:error, HTTPResponse.t()} | {:error, term()}
  def request(method, url, body, headers, config) do
    {http_adapter, opts} = fetch_http_adapter(config)

    method
    |> http_adapter.request(url, body, headers, opts)
    |> parse_status_response(http_adapter, url)
  end

  defp fetch_http_adapter(config) do
    case Config.get(config, :http_adapter, Assent.HTTPAdapter.Httpc) do
      {http_adapter, opts} -> {http_adapter, opts}
      http_adapter         -> {http_adapter, nil}
    end
  end

  defp parse_status_response({:ok, %{status: status} = resp}, _http_adapter, _url) when status in 200..399 do
    {:ok, resp}
  end
  defp parse_status_response({:ok, %{status: status} = resp}, _http_adapter, _url) when status in 400..599 do
    {:error, resp}
  end
  defp parse_status_response({:error, error}, http_adapter, url) do
    [url | _rest] = String.split(url, "?", parts: 2)

    {:error, RequestError.unreachable(http_adapter, url, error)}
  end

  @doc """
  Decodes a request response.
  """
  @spec decode_response({atom(), any()}, Config.t()) :: {atom(), any()}
  def decode_response({status, %{body: body, headers: headers} = resp}, config) do
    case decode_body(headers, body, config) do
      {:ok, body}     -> {status, %{resp | body: body}}
      {:error, error} -> {:error, error}
    end
  end
  def decode_response(any, _config), do: any

  defp decode_body(headers, body, config) do
    case List.keyfind(headers, "content-type", 0) do
      {"content-type", "application/json" <> _rest} ->
        decode_json(body, config)
      {"content-type", "text/javascript" <> _rest} ->
        decode_json(body, config)
      {"content-type", "application/x-www-form-urlencoded" <> _reset} ->
        {:ok, URI.decode_query(body)}
      _any ->
        {:ok, body}
      end
  end

  @doc """
  Decode a JSON response to a map
  """
  @spec decode_json(binary(), Config.t()) :: {:ok, map()} | {:error, term()}
  def decode_json(response, config), do: Config.json_library(config).decode(response)

  @doc """
  Verifies a JWT
  """
  @spec verify_jwt(binary(), binary() | map() | nil, Config.t()) :: {:ok, map()} | {:error, any()}
  def verify_jwt(token, secret, config), do: Assent.JWTAdapter.verify(token, secret, jwt_adapter_opts(config))

  defp jwt_adapter_opts(config), do: Keyword.take(config, [:json_library, :jwt_adapter, :private_key_id])

  @doc """
  Signs a JWT
  """
  @spec sign_jwt(map(), binary(), binary(), Config.t()) :: {:ok, binary()} | {:error, term()}
  def sign_jwt(claims, alg, secret, config), do: Assent.JWTAdapter.sign(claims, alg, secret, jwt_adapter_opts(config))

  @doc """
  Generates a URL
  """
  @spec to_url(binary(), binary(), Keyword.t()) :: binary()
  def to_url(site, uri, params \\ [])
  def to_url(site, uri, []), do: endpoint(site, uri)
  def to_url(site, uri, params) do
    endpoint(site, uri) <> "?" <> URI.encode_query(params)
  end

  defp endpoint(site, <<"/"::utf8, _::binary>> = uri),
    do: site <> uri
  defp endpoint(_site, url),
    do: url

  @doc """
  Normalize API user request response into standard claims

  Based on https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.1
  """
  @spec normalize_userinfo(map(), map()) :: {:ok, map()}
  def normalize_userinfo(claims, extra \\ %{}) do
    standard_claims = Map.take(claims,
      ~w(sub name given_name family_name middle_name nickname
         preferred_username profile picture website email email_verified
         gender birthdate zoneinfo locale phone_number phone_number_verified
         address updated_at))

    {:ok, prune(Map.merge(extra, standard_claims))}
  end

  @doc """
  Recursively prunes map for nil values.
  """
  @spec prune(map) :: map
  def prune(map) do
    map
    |> Enum.map(fn {k, v} -> if is_map(v), do: {k, prune(v)}, else: {k, v} end)
    |> Enum.filter(fn {_, v} -> not is_nil(v) end)
    |> Enum.into(%{})
  end

  @doc false
  def __normalize__({:ok, %{user: user} = results}, config, strategy) do
    config
    |> strategy.normalize(user)
    |> case do
      {:ok, user}        -> normalize_userinfo(user)
      {:ok, user, extra} -> normalize_userinfo(user, extra)
      {:error, error}    -> {:error, error}
    end
    |> case do
      {:error, error} -> {:error, error}
      {:ok, user}     -> {:ok, %{results | user: user}}
    end
  end
  def __normalize__({:error, error}, _config, _strategy), do: {:error, error}
end
