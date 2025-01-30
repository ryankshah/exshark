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
      # Create a sample pcap with more reliable packet generation
      ping_args = ["-c", "4", "-i", "0.2", "127.0.0.1"]

      capture_args = [
        "-w",
        @test_pcap,
        "-F",
        "pcap",
        "-f",
        "icmp or ip",
        "-a",
        "duration:2",
        "-i",
        "any"
      ]

      System.cmd("ping", ping_args)
      {output, status} = System.cmd("tshark", capture_args)

      if status != 0 do
        raise "Failed to create test PCAP: #{output}"
      end
    end

    @test_pcap
  end
end

# Create test PCAP on startup
ExShark.TestHelper.ensure_test_pcap!()
