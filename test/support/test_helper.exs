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
    # More reliable PCAP generation
    System.cmd("ping", ["-c", "4", "8.8.8.8"])
    
    capture_args = [
      "-w", @test_pcap,
      "-F", "pcap",
      "-f", "icmp or ip",
      "-i", "any",
      "-a", "duration:2",
      "-c", "10"  # Capture max 10 packets
    ]
    
    {output, status} = System.cmd("tshark", capture_args)
    
    if status != 0 do
      raise "Failed to create test PCAP: #{output}"
    end
    
    # Verify file was created and contains packets
    unless File.exists?(@test_pcap) && File.stat!(@test_pcap).size > 0 do
      raise "Failed to create valid test PCAP file"
    end
  end
  
  @test_pcap
end

# Create test PCAP on startup
ExShark.TestHelper.ensure_test_pcap!()
