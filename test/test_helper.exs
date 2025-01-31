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
      generate_test_pcap()
    end

    @test_pcap
  end

  def with_test_interface(fun) do
    interface = test_interface()

    # Generate some initial traffic to ensure interface is ready
    generate_test_traffic()

    # Small delay to ensure interface is ready
    Process.sleep(200)

    fun.(interface)
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
    ping_args =
      case :os.type() do
        {:win32, _} -> ["-n", "2", "127.0.0.1"]
        {:unix, :darwin} -> ["-c", "2", "127.0.0.1"]
        _ -> ["-c", "2", "-i", "0.1", "127.0.0.1"]
      end

    System.cmd(
      case :os.type() do
        {:win32, _} -> "ping"
        _ -> "/bin/ping"
      end,
      ping_args,
      stderr_to_stdout: true
    )
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

    receive do
      {^port, {:exit_status, status}} when status in [0, 1] ->
        if File.exists?(temp_file) and File.stat!(temp_file).size > 0 do
          File.cp!(temp_file, @test_pcap)
        else
          raise "Failed to create test PCAP: Empty or missing capture file"
        end

        File.rm(temp_file)

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
