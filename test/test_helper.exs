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

  def get_test_packet(index \\ 0) do
    @test_pcap
    |> ExShark.read_file()
    |> Enum.at(index)
  end

  def get_filtered_packets(filter) do
    @test_pcap
    |> ExShark.read_file(filter: filter)
  end

  def with_test_interface(fun) do
    interface = test_interface()
    fun.(interface)
  end

  def test_interface do
    case :os.type() do
      {:unix, :linux} -> "lo"
      {:unix, :darwin} -> "lo0"
      {:win32, _} -> "\\Device\\NPF_Loopback"
      _ -> "any"
    end
  end

  defp generate_test_pcap do
    # Generate some reliable test traffic
    temp_file = Path.join(System.tmp_dir!(), "temp.pcap")

    capture_args = [
      # Write to temp file
      "-w",
      temp_file,
      # Use PCAP format
      "-F",
      "pcap",
      # Use test interface
      "-i",
      test_interface(),
      # Capture ICMP and TCP
      "-f",
      "icmp or tcp",
      # Capture 10 packets
      "-c",
      "10"
    ]

    # Start capture
    tshark_port =
      Port.open({:spawn_executable, tshark_path()}, [
        :binary,
        :exit_status,
        args: capture_args
      ])

    # Generate some traffic
    ping_target =
      case :os.type() do
        {:win32, _} -> "127.0.0.1"
        _ -> "localhost"
      end

    System.cmd(ping_command(), ping_args(ping_target))

    # Wait for capture to finish
    receive do
      {^tshark_port, {:exit_status, status}} when status in [0, 1] ->
        # Copy temp file to test location if it exists and has content
        if File.exists?(temp_file) and File.stat!(temp_file).size > 0 do
          File.cp!(temp_file, @test_pcap)
        else
          raise "Failed to create test PCAP: Empty or missing capture file"
        end

      {^tshark_port, {:exit_status, status}} ->
        raise "Failed to create test PCAP: tshark exited with status #{status}"
    after
      10_000 ->
        raise "Failed to create test PCAP: timeout"
    end
  end

  defp tshark_path do
    System.find_executable("tshark") ||
      raise "tshark executable not found in PATH"
  end

  defp ping_command do
    case :os.type() do
      {:win32, _} -> "ping"
      _ -> "/bin/ping"
    end
  end

  defp ping_args(target) do
    case :os.type() do
      {:win32, _} -> ["-n", "4", target]
      {:unix, :darwin} -> ["-c", "4", target]
      _ -> ["-c", "4", "-i", "0.2", target]
    end
  end
end
