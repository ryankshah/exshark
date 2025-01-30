# test/test_helper.exs
ExUnit.start()

defmodule ExShark.TestHelper do
  @fixtures_path Path.expand("support/fixtures", __DIR__)
  @test_pcap Path.join(@fixtures_path, "test.pcap")

  def fixtures_path, do: @fixtures_path
  def test_pcap_path, do: @test_pcap

  def fixture_path(filename) do
    Path.join(@fixtures_path, filename)
  end

  def ensure_test_pcap! do
    File.mkdir_p!(Path.dirname(@test_pcap))

    unless File.exists?(@test_pcap) do
      # Create a sample pcap with tshark
      args = [
        "-w",
        @test_pcap,
        "-F",
        "pcap",
        # capture filter
        "-f",
        "ip",
        # capture 10 packets
        "-c",
        "10",
        "-i",
        "any",
        # JSON format
        "-T",
        "ek",
        # don't resolve names
        "-n"
      ]

      {output, status} = System.cmd("tshark", args)

      if status != 0 do
        raise "Failed to create test PCAP: #{output}"
      end
    end

    @test_pcap
  end
end

ExShark.TestHelper.ensure_test_pcap!()
