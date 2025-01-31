defmodule ExShark.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/ryankshah/exshark"

  def project do
    [
      app: :exshark,
      version: @version,
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs(),
      description: description(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.github": :test
      ],
      dialyzer: [
        plt_add_apps: [:mix],
        ignore_warnings: ".dialyzer_ignore.exs"
      ],
    ]
  end

  def application do
    [
      mod: {ExShark.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.2"},
      {:castore, "~> 1.0", optional: true},
      {:ex_doc, "~> 0.29", only: :dev, runtime: false},
      {:excoveralls, "~> 0.15", only: :test},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
    ]
  end

  defp description do
    """
    An Elixir wrapper for tshark (Wireshark's command-line interface) that enables
    packet capture and analysis using Wireshark's powerful dissectors.
    """
  end

  defp package do
    [
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Docs" => "https://hexdocs.pm/exshark"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      extras: ["README.md"],
      groups_for_modules: [
        Core: [
          ExShark,
          ExShark.Packet
        ],
        "Capture Methods": [
          ExShark.LazyCapture,
          ExShark.AsyncCapture
        ],
        "Packet Information": [
          ExShark.Packet.Layer,
          ExShark.Packet.FrameInfo
        ]
      ]
    ]
  end
end
