ExUnit.start()

defmodule ExShark.TestHelper do
  @test_pcap "test/support/fixtures/simple_xml_and_json.pcap"

  def test_pcap_path, do: @test_pcap

  def create_test_pcap do
    unless File.exists?(@test_pcap) do
      File.mkdir_p!(Path.dirname(@test_pcap))
      # Create a simple test PCAP using tshark
      System.cmd("tshark", [
        "-w",
        @test_pcap,
        "-F",
        "pcap",
        # Create 24 packets
        "-c",
        "24",
        # Use any interface
        "-i",
        "any"
      ])
    end
  end
end

# Create test PCAP if it doesn't exist
ExShark.TestHelper.create_test_pcap()
