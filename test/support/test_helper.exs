defmodule ExShark.TestHelper do
  @moduledoc false

  @fixtures_path Path.join([Path.dirname(__ENV__.file), "fixtures"])

  def fixtures_path, do: @fixtures_path

  def fixture_path(filename) do
    Path.join(@fixtures_path, filename)
  end

  def ensure_test_pcap! do
    test_pcap = fixture_path("test.pcap")
    File.mkdir_p!(Path.dirname(test_pcap))

    unless File.exists?(test_pcap) do
      # Create a minimal test PCAP using tcpdump
      {_, 0} =
        System.cmd("tcpdump", [
          "-w",
          test_pcap,
          "-c",
          "1",
          "-i",
          "any"
        ])
    end

    test_pcap
  end
end
