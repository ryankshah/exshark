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
    ensure_test_pcap!()

    @test_pcap
    |> ExShark.read_file()
    |> Enum.at(index)
  end

  def with_test_interface(fun) do
    ensure_test_pcap!()
    fun.(@test_pcap)
  end

  def test_interface, do: @test_pcap

  def ensure_test_pcap! do
    File.mkdir_p!(Path.dirname(@test_pcap))

    unless File.exists?(@test_pcap) do
      generate_test_pcap()
    end

    @test_pcap
  end

  defp generate_test_pcap do
    temp_file = Path.join(System.tmp_dir!(), "temp.pcap")

    capture_args = [
      "-w",
      temp_file,
      "-F",
      "pcap",
      # Ensure we capture some IP traffic
      "-f",
      "icmp or tcp",
      "-c",
      "10"
    ]

    # Start capture
    port =
      Port.open({:spawn_executable, tshark_path()}, [
        :binary,
        :exit_status,
        args: capture_args
      ])

    # Generate some ICMP traffic
    ping_args =
      case :os.type() do
        {:win32, _} -> ["-n", "4", "8.8.8.8"]
        _ -> ["-c", "4", "8.8.8.8"]
      end

    System.cmd(
      case :os.type() do
        {:win32, _} -> "ping"
        _ -> "/bin/ping"
      end,
      ping_args
    )

    receive do
      {^port, {:exit_status, status}} when status in [0, 1] ->
        if File.exists?(temp_file) and File.stat!(temp_file).size > 0 do
          File.cp!(temp_file, @test_pcap)
          File.rm(temp_file)
        else
          raise "Failed to create test PCAP: Empty or missing capture file"
        end

      {^port, {:exit_status, status}} ->
        raise "Failed to create test PCAP: tshark exited with status #{status}"
    after
      10_000 ->
        Port.close(port)
        raise "Failed to create test PCAP: timeout"
    end

    unless File.exists?(@test_pcap) do
      raise "Failed to create test PCAP file"
    end

    @test_pcap
  end

  defp tshark_path do
    System.find_executable("tshark") ||
      raise "tshark executable not found in PATH"
  end
end
