defmodule ExShark do
  @moduledoc """
  ExShark is an Elixir wrapper for tshark (Wireshark's command-line interface) that 
  enables packet capture and analysis using Wireshark's powerful dissectors.
  """

  alias ExShark.{Packet, LazyCapture, AsyncCapture}

  @doc """
  Reads packets from a pcap file and returns them as a list.

  ## Example
      iex> ExShark.read_file("capture.pcap")
      [%ExShark.Packet{...}, ...]
  """
  def read_file(file_path, opts \\ []) do
    filter = Keyword.get(opts, :filter, "")
    fields = Keyword.get(opts, :fields, [])

    args =
      ["-r", file_path, "-T", "ek", "-n"] ++
        build_filter_args(filter) ++
        build_fields_args(fields)

    {output, 0} = System.cmd(find_tshark(), args, stderr_to_stdout: true)

    output
    |> String.split("\n", trim: true)
    |> Enum.map(&Jason.decode!/1)
    |> Enum.map(&Packet.new/1)
  end

  @doc """
  Starts a live capture on the specified interface with given options.
  Returns a stream of parsed packets.

  ## Options
    * `:interface` - Network interface to capture on (default: "any")
    * `:filter` - Display filter string
    * `:duration` - Capture duration in seconds
    * `:packet_count` - Number of packets to capture
    * `:fields` - List of fields to extract

  ## Example
      iex> ExShark.capture(interface: "eth0", filter: "tcp port 80")
      #Stream<...>
  """
  def capture(opts \\ []) do
    interface = Keyword.get(opts, :interface, "any")
    filter = Keyword.get(opts, :filter, "")
    duration = Keyword.get(opts, :duration)
    packet_count = Keyword.get(opts, :packet_count)
    fields = Keyword.get(opts, :fields, [])

    args =
      ["-i", interface, "-T", "ek", "-n"] ++
        build_filter_args(filter) ++
        build_duration_args(duration) ++
        build_count_args(packet_count) ++
        build_fields_args(fields)

    Port.open(
      {:spawn_executable, find_tshark()},
      [:binary, :exit_status, args: args]
    )
    |> stream_output()
    |> Stream.map(&Jason.decode!/1)
    |> Stream.map(&Packet.new/1)
  end

  # Private Functions

  defp find_tshark do
    System.find_executable("tshark") ||
      raise "tshark executable not found in PATH"
  end

  defp build_filter_args(""), do: []
  defp build_filter_args(filter), do: ["-Y", filter]

  defp build_duration_args(nil), do: []
  defp build_duration_args(duration), do: ["-a", "duration:#{duration}"]

  defp build_count_args(nil), do: []
  defp build_count_args(count), do: ["-c", "#{count}"]

  defp build_fields_args([]), do: []
  defp build_fields_args(fields), do: Enum.flat_map(fields, &["-e", &1])

  defp stream_output(port) do
    Stream.resource(
      fn -> port end,
      fn port ->
        receive do
          {^port, {:data, data}} -> {[data], port}
          {^port, {:exit_status, _}} -> {:halt, port}
        end
      end,
      fn port -> Port.close(port) end
    )
  end
end
