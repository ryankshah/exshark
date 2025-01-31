defmodule ExShark.TestHelper do
  @fixtures_path Path.expand("support/fixtures", __DIR__)
  @test_pcap Path.join(@fixtures_path, "test.pcap")
  @loop_pcap Path.join(@fixtures_path, "loop.pcap")

  def fixtures_path, do: @fixtures_path
  def test_pcap_path, do: @test_pcap
  def loop_pcap_path, do: @loop_pcap

  def with_test_interface(fun) do
    interface = test_interface()
    fun.(interface)
  end

  def test_interface do
    case :os.type() do
      {:unix, :linux} -> @loop_pcap
      {:unix, :darwin} -> @loop_pcap
      {:win32, _} -> @loop_pcap
      _ -> @loop_pcap
    end
  end

  def ensure_test_pcap! do
    ensure_pcap_exists!(@test_pcap)
  end

  defp ensure_pcap_exists!(file_path) do
    File.mkdir_p!(Path.dirname(file_path))
    file_path
  end
end
