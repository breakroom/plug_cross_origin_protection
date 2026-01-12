defmodule PlugCrossOriginProtection.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/breakroom/plug_cross_origin_protection"

  def project do
    [
      app: :plug_cross_origin_protection,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "PlugCrossOriginProtection",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:plug, "~> 1.16"},
      {:ex_doc, "~> 0.35", only: :dev, runtime: false}
    ]
  end

  defp description do
    """
    A Plug to protect against Cross-Site Request Forgery (CSRF) attacks using
    modern header-based checks (Sec-Fetch-Site and Origin) instead of tokens.
    """
  end

  defp package do
    [
      maintainers: ["Tom Taylor"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url
      },
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "PlugCrossOriginProtection",
      source_ref: "v#{@version}",
      source_url: @source_url,
      extras: ["README.md", "LICENSE"]
    ]
  end
end
