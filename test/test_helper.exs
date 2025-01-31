defmodule ExShark.TestHelper do
  @fixtures_path Path.expand("support/fixtures", __DIR__)
  @test_pcap Path.join(@fixtures_path, "test.pcap")
  @loop_pcap Path.join(@fixtures_path, "loop.pcap")

  def fixtures_path, do: @fixtures_path
  def test_pcap_path, do: @test_pcap
  def loop_pcap_path, do: @loop_pcap

  @doc """
  Gets a test packet from the test PCAP file.
  """
  def get_test_packet(index \\ 0) do
    @loop_pcap
    |> ExShark.read_file()
    |> Enum.at(index)
  end

  def with_test_interface(fun) do
    fun.(@loop_pcap)
  end

  def test_interface, do: @loop_pcap
end
