defmodule Assent.HTTPAdapter do
  @moduledoc """
  HTTP adapter helper module

  ## Usage

      defmodule MyApp.MyHTTPAdapter do
        @behaviour Assent.HTTPAdapter

        @impl true
        def request(method, url, body, haders, opts) do
          # ...
        end
      end
  """

  defmodule HTTPResponse do
    @moduledoc false

    @type header :: {binary(), binary()}
    @type t      :: %__MODULE__{
      status: integer(),
      headers: [header()],
      body: binary()
    }

    defstruct status: 200, headers: [], body: ""
  end

  @type method :: :get | :post
  @type body :: binary() | nil
  @type headers :: [{binary(), binary()}]

  @callback request(method(), binary(), body(), headers(), Keyword.t()) :: {:ok, map()} | {:error, any()}

  @doc """
  Sets a user agent header

  The header value will be `Assent-VERSION` with VERSION being the `:vsn` of
  `Assent`.
  """
  @spec user_agent_header() :: {binary(), binary()}
  def user_agent_header() do
    version = Application.spec(:assent, :vsn) || "0.0.0"

    {"User-Agent", "Assent-#{version}"}
  end
end
