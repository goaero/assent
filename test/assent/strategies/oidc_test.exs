defmodule Assent.Strategy.OIDCTest do
  use Assent.Test.OIDCTestCase

  alias Assent.{RequestError, Strategy.OIDC}

  describe "authorize_url/2" do
    test "generates url and state", %{config: config, bypass: bypass} do
      assert {:ok, %{url: url, session_params: %{state: state}}} = OIDC.authorize_url(config)

      refute is_nil(state)
      assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
    end

    test "can add nonce", %{config: config, bypass: bypass} do
      assert {:ok, %{url: url, session_params: %{state: state, nonce: nonce}}} =
        config
        |> Keyword.put(:nonce, "n-0S6_WzA2Mj")
        |> OIDC.authorize_url()

      assert nonce == "n-0S6_WzA2Mj"
      assert url =~ "http://localhost:#{bypass.port}/oauth/authorize?client_id=id&nonce=n-0S6_WzA2Mj&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fauth%2Fcallback&response_type=code&scope=openid&state=#{state}"
    end
  end

  describe "callback/2 with static OpenID configuration" do
    test "with missing `token_endpoint` configuration options", %{config: config, callback_params: params} do
      openid_config =
        config
        |> Keyword.get(:openid_configuration)
        |> Map.delete("token_endpoint")

      config = Keyword.put(config, :openid_configuration, openid_config)

      assert OIDC.callback(config, params) == {:error, "`token_endpoint` not found in OpenID configuration"}
    end

    test "with invalid id_token", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, [id_token: "invalid"])

      assert OIDC.callback(config, params) == {:error, "The ID Token is not a valid JWT"}
    end

    @user_claims %{sub: "1", name: "Dan Schultzer", email: "foo@example.com", email_verified: true}
    @user %{"email" => "foo@example.com", "name" => "Dan Schultzer", "sub" => "1", "email_verified" => true}

    test "with `client_secret_basic` authentication method", %{config: config, callback_params: params, bypass: bypass} do
      expect_oidc_access_token_request(bypass, [id_token_opts: [claims: @user_claims, iss: "http://localhost"]], fn conn, _params ->
        assert [{"authorization", "Basic " <> token} | _rest] = conn.req_headers
        assert [client_id, client_secret] = String.split(Base.url_decode64!(token, padding: false), ":")

        assert client_id == config[:client_id]
        assert client_secret == config[:client_secret]
      end)

      expect_oidc_jwks_uri_request(bypass, count: 1)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end

    @private_rsa_key """
      -----BEGIN RSA PRIVATE KEY-----
      MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
      kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
      m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
      NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
      3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
      QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
      kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
      amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
      +bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
      D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
      0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
      lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
      hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
      bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
      +jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
      BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
      2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
      QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
      5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
      Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
      NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
      8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
      3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
      y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
      jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
      -----END RSA PRIVATE KEY-----
      """
    @public_rsa_key """
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      MwIDAQAB
      -----END PUBLIC KEY-----
      """

    test "with `private_key_jwt` authentication method", %{config: config, callback_params: params, bypass: bypass} do
      openid_configuration =
        config[:openid_configuration]
        |> Map.put("client_authentication_method", "private_key_jwt")
        |> Map.put("token_endpoint_auth_methods_supported", ["private_key_jwt"])

      config =
        config
        |> Keyword.put(:client_authentication_method, "private_key_jwt")
        |> Keyword.put(:openid_configuration, openid_configuration)
        |> Keyword.put(:private_key, @private_rsa_key)
        |> Keyword.put(:private_key_id, "key_id")

      expect_oidc_access_token_request(bypass, [id_token_opts: [claims: @user_claims, iss: "http://localhost"]], fn _conn, params ->
        assert {:ok, jwt} = Assent.JWTAdapter.AssentJWT.verify(params["client_assertion"], @public_rsa_key, json_library: Jason)
        assert jwt.header["alg"] == "RS256"
        assert jwt.header["typ"] == "JWT"
        assert jwt.header["kid"] == "key_id"
        assert jwt.claims["iss"] == "id"
        assert jwt.claims["sub"] == "id"
        assert jwt.claims["aud"] == "http://localhost:#{bypass.port}"
        assert jwt.claims["exp"] > DateTime.to_unix(DateTime.utc_now())
      end)

      expect_oidc_jwks_uri_request(bypass, count: 1)

      assert {:ok, %{user: user, token: token}} = OIDC.callback(config, params)
      assert user == @user
      assert %{"access_token" => "access_token", "id_token" => _id_token} = token
    end
  end

  describe "callback/2 with dynamic OpenID configuration" do
    setup %{config: config, bypass: bypass} do
      config = Keyword.delete(config, :openid_configuration)

      openid_config = %{
        "token_endpoint" => "/dynamic/token/path",
        "jwks_uri" => "http://localhost:#{bypass.port}/jwks_uri.json",
        "issuer" => config[:site]
      }

      {:ok, config: config, openid_config: openid_config}
    end

    test "with invalid id_token", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path", id_token: "invalid")

      assert OIDC.callback(config, params) == {:error, "The ID Token is not a valid JWT"}
    end

    test "with valid id_token", %{config: config, openid_config: openid_config, callback_params: params, bypass: bypass} do
      expect_openid_config_request(bypass, openid_config)

      expect_oidc_access_token_request(bypass, uri: "/dynamic/token/path")

      expect_oidc_jwks_uri_request(bypass, count: 1)

      assert {:ok, %{user: user}} = OIDC.callback(config, params)
      assert user == %{"sub" => "1"}
    end
  end

  describe "validate_id_token/2 with `alg=none`" do
    setup %{config: config} do
      JOSE.unsecured_signing(true)
      id_token = gen_id_token(alg: "none")
      config   = Keyword.put(config, :id_token_signed_response_alg, "none")

      {:ok, id_token: id_token, config: config}
    end

    test "fails", %{config: config, id_token: id_token} do
      assert OIDC.validate_id_token(config, id_token) == {:error, "Invalid JWT signature for ID Token"}
    end
  end

  describe "validate_id_token/2 with `alg=HS256`" do
    setup %{config: config} do
      id_token = gen_id_token(alg: "HS256")
      config   = Keyword.put(config, :id_token_signed_response_alg, "HS256")

      {:ok, id_token: id_token, config: config}
    end

    test "with no `:openid_configuration`", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :openid_configuration)

      assert {:error, %Assent.Config.MissingKeyError{} = error} = OIDC.validate_id_token(config, id_token)
      assert error.message == "Key `:openid_configuration` not found in config"
    end

    test "with no `:client_id`", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :client_id)

      assert {:error, %Assent.Config.MissingKeyError{} = error} = OIDC.validate_id_token(config, id_token)
      assert error.message == "Key `:client_id` not found in config"
    end

    test "with missing `issuer` in OpenID configuration", %{config: config, id_token: id_token} do
      openid_config = Map.delete(Keyword.get(config, :openid_configuration), "issuer")
      config        = Keyword.put(config, :openid_configuration, openid_config)

      assert OIDC.validate_id_token(config, id_token) == {:error, "`issuer` not found in OpenID configuration"}
    end

    test "with invalid id_token", %{config: config} do
      assert OIDC.validate_id_token(config, "invalid") == {:error, "The ID Token is not a valid JWT"}
    end

    test "with no `:client_secret`", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :client_secret)

      assert {:error, %Assent.Config.MissingKeyError{} = error} = OIDC.validate_id_token(config, id_token)
      assert error.message == "Key `:client_secret` not found in config"
    end

    for key <- ~w(iss sub aud exp iat) do
      test "with missing required #{key} keys in id_token", %{config: config} do
        id_token = gen_id_token(alg: "HS256", claims: %{unquote(key) => nil})

        assert OIDC.validate_id_token(config, id_token) == {:error, "Missing `#{unquote(key)}` in ID Token claims"}
      end
    end

    test "with invalid `issuer` in id_token", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"iss" => "invalid"})

      assert OIDC.validate_id_token(config, id_token) == {:error, "Invalid issuer \"invalid\" in ID Token"}
    end

    test "with unexpected `alg`", %{config: config, id_token: id_token} do
      assert OIDC.validate_id_token(Keyword.delete(config, :id_token_signed_response_alg), id_token) == {:error, "Expected `alg` in ID Token to be \"RS256\", got \"HS256\""}

      JOSE.unsecured_signing(true)
      id_token = gen_id_token(alg: "none")

      assert OIDC.validate_id_token(config, id_token) == {:error, "Expected `alg` in ID Token to be \"HS256\", got \"none\""}
    end

    test "with invalid `aud` in id_token", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"aud" => "invalid"})

      assert OIDC.validate_id_token(config, id_token) == {:error, "Invalid audience \"invalid\" in ID Token"}
    end

    test "with invalid signature in id_token", %{config: config, id_token: id_token} do
      [header, payload, _signature] = String.split(id_token, ".")
      id_token                      = "#{header}.#{payload}.invalid"

      assert OIDC.validate_id_token(config, id_token) == {:error, "Invalid JWT signature for ID Token"}
    end

    test "with expired id_token", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"exp" => :os.system_time(:second)})

      assert OIDC.validate_id_token(config, id_token) == {:error, "The ID Token has expired"}
    end

    test "with TTL reached for id_token", %{config: config} do
      config   = Keyword.put(config, :id_token_ttl_seconds, 60)
      id_token = gen_id_token(alg: "HS256", claims: %{"iat" => :os.system_time(:second) - 60})

      assert OIDC.validate_id_token(config, id_token) == {:error, "The ID Token was issued too long ago"}
    end

    test "with missing `:session_params` config", %{config: config, id_token: id_token} do
      config = Keyword.delete(config, :session_params)

      assert {:error, %Assent.Config.MissingKeyError{} = error} = OIDC.validate_id_token(config, id_token)
      assert error.message == "Key `:session_params` not found in config"
    end

    test "without nonce", %{config: config, id_token: id_token} do
      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end

    test "with unexpected `nonce` in id_token", %{config: config} do
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert OIDC.validate_id_token(config, id_token) == {:error, "`nonce` included in ID Token but doesn't exist in session params"}
    end

    test "with missing `nonce` in id_token", %{config: config, id_token: id_token} do
      config = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "n-0S6_WzA2Mj"))

      assert OIDC.validate_id_token(config, id_token) == {:error, "`nonce` is not included in ID Token"}
    end

    test "with invalid `nonce` in id_token", %{config: config} do
      config   = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "b"))
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert OIDC.validate_id_token(config, id_token) == {:error, "Invalid `nonce` included in ID Token"}
    end

    test "with valid nonce in id_token", %{config: config} do
      config   = Keyword.put(config, :session_params, Map.put(config[:session_params], :nonce, "a"))
      id_token = gen_id_token(alg: "HS256", claims: %{"nonce" => "a"})

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end
  end

  describe "validate_id_token/2 with `alg=RS256`" do
    setup %{config: config} do
      id_token = gen_id_token()

      {:ok, config: config, id_token: id_token}
    end

    test "with missing `jwks_uri` in OpenID configuration", %{config: config, id_token: id_token} do
      openid_config = Map.delete(Keyword.get(config, :openid_configuration), "jwks_uri")
      config = Keyword.put(config, :openid_configuration, openid_config)

      assert OIDC.validate_id_token(config, id_token) == {:error, "`jwks_uri` not found in OpenID configuration"}
    end

    test "with 404 `jwks_uri` url", %{config: config, id_token: id_token, bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/jwks_uri.json", fn conn ->
        Plug.Conn.send_resp(conn, 404, "")
      end)

      assert {:error, %Assent.RequestError{} = error} = OIDC.validate_id_token(config, id_token)
      assert error.error == :invalid_server_response
      assert error.message =~ "Server responded with status: 404"
    end

    test "with missing keys in `jwks_uri` url", %{config: config, id_token: id_token, bypass: bypass} do
      Bypass.expect_once(bypass, "GET", "/jwks_uri.json", fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("application/json")
        |> Plug.Conn.send_resp(200, "{}")
      end)

      assert OIDC.validate_id_token(config, id_token) == {:error, "No keys found in `jwks_uri` provider configuration"}
    end

    test "with no `kid` in header and multiple keys fetched from `jwks_uri` url", %{config: config, id_token: id_token, bypass: bypass} do
      expect_oidc_jwks_uri_request(bypass)

      assert OIDC.validate_id_token(config, id_token) == {:error, "Multiple public keys found in provider configuration and no `kid` value in ID Token"}
    end

    test "with no `kid` in header and single key fetched from `jwks_uri` url", %{config: config, id_token: id_token, bypass: bypass} do
      expect_oidc_jwks_uri_request(bypass, count: 1)

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end

    test "with no matching `kid` in keys fetched from `jwks_uri` url", %{config: config, bypass: bypass} do
      id_token = gen_id_token(kid: "invalid")

      expect_oidc_jwks_uri_request(bypass)

      assert OIDC.validate_id_token(config, id_token) == {:error, "No keys found for the `kid` value \"invalid\" provided in ID Token"}
    end

    test "with matching `kid` in keys fetched from `jwks_uri` url", %{config: config, bypass: bypass} do
      id_token = gen_id_token(kid: "key-1")

      expect_oidc_jwks_uri_request(bypass)

      assert {:ok, jwt} = OIDC.validate_id_token(config, id_token)
      assert jwt.verified?
      assert jwt.claims["sub"] == "1"
    end
  end

  describe "fetch_userinfo/2" do
    setup %{config: config} do
      id_token     = gen_id_token(alg: "HS256")
      config       = Keyword.put(config, :id_token_signed_response_alg, "HS256")
      access_token = %{"access_token" => "access_token", "id_token" => id_token}

      {:ok, config: config, access_token: access_token}
    end

    test "with no `:openid_configuration`", %{config: config, access_token: access_token} do
      config = Keyword.delete(config, :openid_configuration)

      assert {:error, %Assent.Config.MissingKeyError{} = error} = OIDC.fetch_userinfo(config, access_token)
      assert error.message == "Key `:openid_configuration` not found in config"
    end

    test "with missing `userinfo_endpoint` in OpenID configuration", %{config: config, access_token: access_token} do
      openid_configuration = Map.delete(config[:openid_configuration], "userinfo_endpoint")
      config               = Keyword.put(config, :openid_configuration, openid_configuration)

      assert OIDC.fetch_userinfo(config, access_token) == {:error, "`userinfo_endpoint` not found in OpenID configuration"}
    end

    test "with unreachable `userinfo_endpoint`", %{config: config, access_token: access_token} do
      openid_configuration = Map.put(config[:openid_configuration], "userinfo_endpoint", "http://localhost:8888/userinfo")
      config               = Keyword.put(config, :openid_configuration, openid_configuration)

      assert {:error, %RequestError{} = error} = OIDC.fetch_userinfo(config, access_token)
      assert error.error == :unreachable
      assert error.message =~ "Server was unreachable with Assent.HTTPAdapter.Httpc."
      assert error.message =~ "{:failed_connect"
      assert error.message =~ "URL: http://localhost:8888/userinfo"
    end

    test "with unauthorized `userinfo_endpoint`", %{config: config, access_token: access_token, bypass: bypass} do
      expect_oidc_userinfo_request(bypass, %{"error" => "Unauthorized"}, status_code: 401)

      assert {:error, %RequestError{} = error} = OIDC.fetch_userinfo(config, access_token)
      assert error.message == "Unauthorized token"
      refute error.error
    end

    test "with jwt response with invalid signature", %{config: config, access_token: access_token, bypass: bypass} do
      [header, payload, _signature] = String.split(gen_id_token(alg: "HS256"), ".")
      expect_oidc_userinfo_request(bypass, "#{header}.#{payload}.invalid")

      assert OIDC.fetch_userinfo(config, access_token) == {:error, "Invalid JWT signature for ID Token"}
    end

    test "with jwt response", %{config: config, access_token: access_token, bypass: bypass} do
      expect_oidc_userinfo_request(bypass, gen_id_token(alg: "HS256"))

      assert {:ok, %{"sub" => "1"}} = OIDC.fetch_userinfo(config, access_token)
    end

    test "with missing `sub` in userinfo claims", %{config: config, access_token: access_token, bypass: bypass} do
      expect_oidc_userinfo_request(bypass, Map.delete(@user_claims, :sub))

      assert OIDC.fetch_userinfo(config, access_token) == {:error, "`sub` not in userinfo response"}
    end

    test "with different `sub` in userinfo claims", %{config: config, access_token: access_token, bypass: bypass} do
      expect_oidc_userinfo_request(bypass, Map.put(@user_claims, :sub, "2"))

      assert OIDC.fetch_userinfo(config, access_token) == {:error, "`sub` in userinfo response not the same as in ID Token"}
    end
  end
end
