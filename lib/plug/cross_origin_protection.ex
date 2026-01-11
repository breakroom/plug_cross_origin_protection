defmodule Plug.CrossOriginProtection do
  @moduledoc """
  Plug to protect from cross-site request forgery (CSRF) using header-based
  checks.

  Unlike token-based CSRF protection, this plug uses modern browser headers
  (`Sec-Fetch-Site` and `Origin`) to detect and reject cross-origin requests.
  This approach requires no session state or token management.

  For this plug to be effective, state-changing actions must not be performed
  on GET, HEAD, or OPTIONS requests, as these are always allowed.

  ## How it works

  1. Safe methods (GET, HEAD, OPTIONS) are always allowed
  2. If `Origin` header matches a trusted origin, the request is allowed
  3. If `Sec-Fetch-Site` header is `same-origin` or `none`, the request is allowed
  4. If `Sec-Fetch-Site` indicates cross-origin, the request is rejected
  5. If no `Sec-Fetch-Site` or `Origin` headers are present, the request is allowed
     (non-browser requests like curl or API clients)
  6. If only `Origin` is present, it's compared against the `Host` header

  ## Options

    * `:trusted_origins` - an optional list of trusted origin strings that bypass
      protection. Origins must be in the format `"scheme://host"` or
      `"scheme://host:port"`.  Example: `["https://sso.example.com",
      "https://partner.example.com:8443"]`

    * `:with` - should be one of `:exception` or `:forbidden`. Defaults to `:forbidden`.
      * `:exception` - raises `Plug.CrossOriginProtection.InvalidCrossOriginRequestError`
      * `:forbidden` - returns a 403 Forbidden response

  ## Disabling

  You may disable this plug by calling `Plug.CrossOriginProtection.skip/1` on
  the `Plug.Conn`, or by setting
  `Plug.Conn.put_private(conn, :plug_skip_cross_origin_protection, true)`.

  This is useful for:

    * SSO/OAuth callback endpoints
    * Webhook endpoints that receive cross-origin requests
    * Public API endpoints

  ## Examples

      # Basic usage
      plug Plug.CrossOriginProtection

      # With trusted origins
      plug Plug.CrossOriginProtection,
        trusted_origins: ["https://sso.example.com"]

      # Raise exception instead of 403
      plug Plug.CrossOriginProtection, with: :exception

  ## Security Considerations

    * Ensure state-changing actions are never performed on GET requests
    * Use HTTPS - the `Sec-Fetch-Site` header is only sent to secure origins
    * Consider using HSTS to protect against HTTP->HTTPS attacks on older browsers
    * `Sec-Fetch-Site` is supported in all major browsers since 2023

  ## References

    * [Cross-Site Request Forgery](https://words.filippo.io/csrf/) - Filippo Valsorda's blog post
    * [Go net/http CrossOriginProtection](https://pkg.go.dev/net/http@go1.25rc2#CrossOriginProtection)
    * [Sec-Fetch-Site MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site)
  """

  import Plug.Conn

  @behaviour Plug

  @safe_methods ~w(GET HEAD OPTIONS)

  defmodule InvalidCrossOriginRequestError do
    @moduledoc """
    Error raised when a cross-origin request is detected.

    This exception is raised when the `:with` option is set to `:exception`
    and a cross-origin request is detected.
    """

    defexception message: "cross-origin request detected", plug_status: 403
  end

  @doc """
  Marks the connection to skip cross-origin protection checks.

  This should be used sparingly for legitimate cross-origin endpoints like:
    * SSO/OAuth callbacks
    * Webhook endpoints
    * Public API endpoints

  ## Example

      def call(conn, _opts) do
        conn
        |> Plug.CrossOriginProtection.skip()
        |> MyApp.Router.call([])
      end

  """
  def skip(conn) do
    put_private(conn, :plug_skip_cross_origin_protection, true)
  end

  # Plug callbacks

  @impl true
  def init(opts) do
    trusted_origins =
      opts
      |> Keyword.get(:trusted_origins, [])
      |> validate_origins!()
      |> MapSet.new()

    mode = Keyword.get(opts, :with, :forbidden)

    unless mode in [:exception, :forbidden] do
      raise ArgumentError,
            "option :with should be one of :exception or :forbidden, got #{inspect(mode)}"
    end

    {trusted_origins, mode}
  end

  @impl true
  def call(conn, {trusted_origins, mode}) do
    if skip_protection?(conn) or verified_request?(conn, trusted_origins) do
      conn
    else
      handle_invalid_request(conn, mode)
    end
  end

  # Private helpers

  defp skip_protection?(%Plug.Conn{private: %{plug_skip_cross_origin_protection: true}}), do: true
  defp skip_protection?(%Plug.Conn{}), do: false

  defp verified_request?(conn, trusted_origins) do
    cond do
      # Step 1: Safe methods are always allowed
      conn.method in @safe_methods ->
        true

      # Step 2: Check trusted origins allow-list
      trusted_origin?(conn, trusted_origins) ->
        true

      # Step 3: Sec-Fetch-Site indicates same-origin or user-initiated
      get_sec_fetch_site(conn) in ["same-origin", "none"] ->
        true

      # Step 3b: Sec-Fetch-Site is present but cross-origin - reject
      get_sec_fetch_site(conn) != nil ->
        false

      # Step 4: No Sec-Fetch-Site or Origin headers - not a browser, allow
      get_origin(conn) == nil ->
        true

      # Step 5: Origin fallback - compare Origin host with Host header
      true ->
        origin_matches_host?(get_origin(conn), conn.host)
    end
  end

  defp trusted_origin?(conn, trusted_origins) do
    case get_origin(conn) do
      nil -> false
      origin -> MapSet.member?(trusted_origins, normalize_origin_header(origin))
    end
  end

  defp get_origin(conn) do
    conn |> get_req_header("origin") |> List.first()
  end

  defp get_sec_fetch_site(conn) do
    conn |> get_req_header("sec-fetch-site") |> List.first()
  end

  defp origin_matches_host?(origin, host) do
    case URI.parse(origin) do
      %URI{host: origin_host, port: port, scheme: scheme} when is_binary(origin_host) ->
        # Build host string with port if non-default
        origin_host_with_port = build_host_with_port(origin_host, port, scheme)
        origin_host_with_port == host

      _ ->
        false
    end
  end

  defp build_host_with_port(host, nil, _scheme), do: host
  defp build_host_with_port(host, 443, "https"), do: host
  defp build_host_with_port(host, 80, "http"), do: host
  defp build_host_with_port(host, port, _scheme), do: "#{host}:#{port}"

  defp handle_invalid_request(_conn, :exception) do
    raise InvalidCrossOriginRequestError
  end

  defp handle_invalid_request(conn, :forbidden) do
    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(403, "cross-origin request detected")
    |> halt()
  end

  defp validate_origins!(origins) do
    Enum.map(origins, fn origin ->
      uri = URI.parse(origin)

      cond do
        uri.scheme not in ["http", "https"] ->
          raise ArgumentError,
                "invalid origin #{inspect(origin)}: scheme must be http or https"

        is_nil(uri.host) or uri.host == "" ->
          raise ArgumentError,
                "invalid origin #{inspect(origin)}: host is required"

        not is_nil(uri.path) and uri.path not in ["", "/"] ->
          raise ArgumentError,
                "invalid origin #{inspect(origin)}: path is not allowed"

        not is_nil(uri.query) ->
          raise ArgumentError,
                "invalid origin #{inspect(origin)}: query is not allowed"

        not is_nil(uri.fragment) ->
          raise ArgumentError,
                "invalid origin #{inspect(origin)}: fragment is not allowed"

        true ->
          # Normalize: scheme://host or scheme://host:port (non-default port only)
          normalize_origin(uri)
      end
    end)
  end

  defp normalize_origin(%URI{scheme: scheme, host: host, port: port}) do
    default_port = if scheme == "https", do: 443, else: 80

    if is_nil(port) or port == default_port do
      "#{scheme}://#{host}"
    else
      "#{scheme}://#{host}:#{port}"
    end
  end

  # Normalize an Origin header value for comparison with trusted origins
  defp normalize_origin_header(origin) when is_binary(origin) do
    case URI.parse(origin) do
      %URI{scheme: scheme, host: host, port: port} when is_binary(scheme) and is_binary(host) ->
        normalize_origin(%URI{scheme: scheme, host: host, port: port})

      _ ->
        origin
    end
  end
end
