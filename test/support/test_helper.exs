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
      # Generate repeatable ICMP traffic
      ping_args = ["-c", "4", "-i", "0.2", "8.8.8.8"]

      # Capture args for tshark
      capture_args = [
        # Write to file
        "-w",
        @test_pcap,
        # Use PCAP format
        "-F",
        "pcap",
        # Capture for 2 seconds
        "-a",
        "duration:2",
        # Capture on any interface
        "-i",
        "any"
      ]

      # Generate traffic
      System.cmd("ping", ping_args)

      # Capture the traffic
      {output, status} = System.cmd("tshark", capture_args)

      if status != 0 do
        raise "Failed to create test PCAP: #{output}"
      end

      # Verify file was created
      unless File.exists?(@test_pcap) do
        raise "Failed to create test PCAP file"
      end
    end

    @test_pcap
  end
end

# Create test PCAP on startup
ExShark.TestHelper.ensure_test_pcap!()
