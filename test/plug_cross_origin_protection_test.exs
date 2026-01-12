defmodule PlugCrossOriginProtectionTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias PlugCrossOriginProtection
  alias PlugCrossOriginProtection.InvalidCrossOriginRequestError

  @opts PlugCrossOriginProtection.init([])

  # Helper to set host on conn
  defp with_host(conn, host), do: %{conn | host: host}

  describe "safe methods" do
    test "allows GET requests" do
      conn = conn(:get, "/") |> PlugCrossOriginProtection.call(@opts)
      refute conn.halted
    end

    test "allows HEAD requests" do
      conn = conn(:head, "/") |> PlugCrossOriginProtection.call(@opts)
      refute conn.halted
    end

    test "allows OPTIONS requests" do
      conn = conn(:options, "/") |> PlugCrossOriginProtection.call(@opts)
      refute conn.halted
    end

    test "allows GET even with cross-site header" do
      conn =
        conn(:get, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end
  end

  describe "Sec-Fetch-Site header" do
    test "allows same-origin requests" do
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "same-origin")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end

    test "allows none (user-initiated) requests" do
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "none")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end

    test "rejects cross-site requests" do
      assert_raise InvalidCrossOriginRequestError, "cross-origin request detected", fn ->
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "rejects same-site (cross-origin) requests" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "same-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end
  end

  describe "Origin header fallback (no Sec-Fetch-Site)" do
    test "allows when Origin host matches Host" do
      conn =
        conn(:post, "/")
        |> with_host("example.com")
        |> put_req_header("origin", "https://example.com")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end

    test "allows when Origin host matches Host with http scheme" do
      conn =
        conn(:post, "/")
        |> with_host("example.com")
        |> put_req_header("origin", "http://example.com")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end

    test "allows with matching host and non-default port" do
      conn =
        conn(:post, "/")
        |> with_host("example.com:8443")
        |> put_req_header("origin", "https://example.com:8443")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end

    test "rejects when Origin host doesn't match Host" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:post, "/")
        |> with_host("example.com")
        |> put_req_header("origin", "https://attacker.com")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "rejects when ports don't match" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:post, "/")
        |> with_host("example.com")
        |> put_req_header("origin", "https://example.com:8443")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "allows requests with no Origin or Sec-Fetch-Site (non-browser)" do
      conn =
        conn(:post, "/")
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end
  end

  describe "trusted origins" do
    @opts_with_trusted PlugCrossOriginProtection.init(
                         trusted_origins: [
                           "https://trusted.example.com",
                           "https://also-trusted.example.com:8443"
                         ]
                       )

    test "allows requests from trusted origins" do
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> put_req_header("origin", "https://trusted.example.com")
        |> PlugCrossOriginProtection.call(@opts_with_trusted)

      refute conn.halted
    end

    test "allows trusted origin with non-default port" do
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> put_req_header("origin", "https://also-trusted.example.com:8443")
        |> PlugCrossOriginProtection.call(@opts_with_trusted)

      refute conn.halted
    end

    test "allows trusted origin with default port in header" do
      # Origin header includes :443 but trusted list has it normalized
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> put_req_header("origin", "https://trusted.example.com:443")
        |> PlugCrossOriginProtection.call(@opts_with_trusted)

      refute conn.halted
    end

    test "rejects untrusted origins" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> put_req_header("origin", "https://untrusted.example.com")
        |> PlugCrossOriginProtection.call(@opts_with_trusted)
      end
    end
  end

  describe "skip mechanism" do
    test "skips check when private flag is set" do
      conn =
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> Plug.Conn.put_private(:plug_skip_cross_origin_protection, true)
        |> PlugCrossOriginProtection.call(@opts)

      refute conn.halted
    end
  end

  describe "exception mode" do
    @opts_exception PlugCrossOriginProtection.init(with: :exception)

    test "raises InvalidCrossOriginRequestError" do
      assert_raise InvalidCrossOriginRequestError, "cross-origin request detected", fn ->
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts_exception)
      end
    end

    test "exception has plug_status 403" do
      assert %InvalidCrossOriginRequestError{plug_status: 403} =
               %InvalidCrossOriginRequestError{}
    end
  end

  describe "init/1 validation" do
    test "accepts empty options" do
      assert {%MapSet{}, :exception} = PlugCrossOriginProtection.init([])
    end

    test "validates origin scheme" do
      assert_raise ArgumentError, ~r/scheme must be http or https/, fn ->
        PlugCrossOriginProtection.init(trusted_origins: ["ftp://example.com"])
      end
    end

    test "validates origin host is present" do
      assert_raise ArgumentError, ~r/host is required/, fn ->
        PlugCrossOriginProtection.init(trusted_origins: ["https://"])
      end
    end

    test "validates origin has no path" do
      assert_raise ArgumentError, ~r/path is not allowed/, fn ->
        PlugCrossOriginProtection.init(trusted_origins: ["https://example.com/path"])
      end
    end

    test "allows origin with trailing slash" do
      {trusted, _mode} = PlugCrossOriginProtection.init(trusted_origins: ["https://example.com/"])
      assert MapSet.member?(trusted, "https://example.com")
    end

    test "validates origin has no query" do
      assert_raise ArgumentError, ~r/query is not allowed/, fn ->
        PlugCrossOriginProtection.init(trusted_origins: ["https://example.com?query=1"])
      end
    end

    test "validates origin has no fragment" do
      assert_raise ArgumentError, ~r/fragment is not allowed/, fn ->
        PlugCrossOriginProtection.init(trusted_origins: ["https://example.com#fragment"])
      end
    end

    test "validates :with option" do
      assert_raise ArgumentError, ~r/should be one of :exception or :forbidden/, fn ->
        PlugCrossOriginProtection.init(with: :invalid)
      end
    end

    test "accepts :exception mode" do
      {_trusted, mode} = PlugCrossOriginProtection.init(with: :exception)
      assert mode == :exception
    end

    test "normalizes origins with default ports" do
      {trusted, _mode} =
        PlugCrossOriginProtection.init(
          trusted_origins: ["https://example.com:443", "http://example.com:80"]
        )

      assert MapSet.member?(trusted, "https://example.com")
      assert MapSet.member?(trusted, "http://example.com")
      refute MapSet.member?(trusted, "https://example.com:443")
      refute MapSet.member?(trusted, "http://example.com:80")
    end

    test "preserves non-default ports" do
      {trusted, _mode} =
        PlugCrossOriginProtection.init(trusted_origins: ["https://example.com:8443"])

      assert MapSet.member?(trusted, "https://example.com:8443")
    end
  end

  describe "HTTP methods" do
    test "rejects POST with cross-site header" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:post, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "rejects PUT with cross-site header" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:put, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "rejects PATCH with cross-site header" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:patch, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end

    test "rejects DELETE with cross-site header" do
      assert_raise InvalidCrossOriginRequestError, fn ->
        conn(:delete, "/")
        |> put_req_header("sec-fetch-site", "cross-site")
        |> PlugCrossOriginProtection.call(@opts)
      end
    end
  end
end
