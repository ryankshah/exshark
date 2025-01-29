ExUnit.start()

defmodule ExShark.TestHelper do
  @fixtures_path Path.expand("support/fixtures", __DIR__)

  def fixtures_path, do: @fixtures_path

  def fixture_path(filename) do
    Path.join(@fixtures_path, filename)
  end

  def ensure_test_pcap! do
    test_pcap = fixture_path("test.pcap")
    File.mkdir_p!(Path.dirname(test_pcap))

    unless File.exists?(test_pcap) do
      {_, 0} =
        System.cmd("tshark", [
          "-w",
          test_pcap,
          "-F",
          "pcap",
          "-c",
          "1",
          "-i",
          "any"
        ])
    end

    test_pcap
  end
end
