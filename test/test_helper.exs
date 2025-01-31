defmodule ExShark.TestHelper do
  @fixtures_path Path.expand("support/fixtures", __DIR__)
  @test_pcap Path.join(@fixtures_path, "test.pcap")

  def fixtures_path, do: @fixtures_path
  def test_pcap_path, do: @test_pcap

  def fixture_path(filename) do
    Path.join(@fixtures_path, filename)
  end

  @doc """
  Gets a test packet from the test PCAP file.
  """
  def get_test_packet(index \\ 0) do
    ensure_test_pcap!()

    @test_pcap
    |> ExShark.read_file()
    |> Enum.at(index)
  end

  def ensure_test_pcap! do
    File.mkdir_p!(Path.dirname(@test_pcap))

    unless File.exists?(@test_pcap) do
      generate_test_pcap()
    end

    # Verify the file exists and has content
    if not File.exists?(@test_pcap) or File.stat!(@test_pcap).size == 0 do
      generate_test_pcap()
    end

    @test_pcap
  end

  def with_test_interface(fun) do
    interface = test_interface()

    # Generate some initial traffic to ensure interface is ready
    generate_test_traffic()

    # Give the interface time to process the traffic
    Process.sleep(500)

    result = fun.(interface)

    # Clean up any remaining processes
    Process.sleep(100)

    result
  end

  def test_interface do
    case :os.type() do
      {:unix, :linux} -> "lo"
      {:unix, :darwin} -> "lo0"
      {:win32, _} -> "\\Device\\NPF_Loopback"
      _ -> "lo"
    end
  end

  defp generate_test_traffic do
    # Send multiple pings to ensure we get some traffic
    1..3
    |> Enum.each(fn _ ->
      ping_args =
        case :os.type() do
          {:win32, _} -> ["-n", "1", "127.0.0.1"]
          {:unix, :darwin} -> ["-c", "1", "127.0.0.1"]
          _ -> ["-c", "1", "-i", "0.1", "127.0.0.1"]
        end

      System.cmd(
        case :os.type() do
          {:win32, _} -> "ping"
          _ -> "/bin/ping"
        end,
        ping_args,
        stderr_to_stdout: true
      )
    end)
  end

  defp generate_test_pcap do
    temp_file = Path.join(System.tmp_dir!(), "temp.pcap")

    capture_args = [
      "-w",
      temp_file,
      "-F",
      "pcap",
      "-i",
      test_interface(),
      "-f",
      "icmp or tcp",
      "-c",
      "10"
    ]

    port =
      Port.open({:spawn_executable, tshark_path()}, [
        :binary,
        :exit_status,
        args: capture_args
      ])

    # Generate traffic while capturing
    generate_test_traffic()

    # Wait for capture to complete
    receive do
      {^port, {:exit_status, status}} when status in [0, 1] ->
        # Give file system time to flush
        Process.sleep(100)

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
  end

  defp tshark_path do
    System.find_executable("tshark") ||
      raise "tshark executable not found in PATH"
  end
end
