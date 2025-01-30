defmodule ExShark do
  @moduledoc """
  ExShark is an Elixir wrapper for tshark (Wireshark's command-line interface) that enables
  packet capture and analysis using Wireshark's powerful dissectors.
  """

  alias ExShark.Packet

  @doc """
  Reads packets from a pcap file and returns them as a list.

  ## Example
      iex> path = Path.join([__DIR__, "../../test/support/fixtures/test.pcap"])
      iex> packets = ExShark.read_file(path)
      iex> is_list(packets)
      true
  """
  def read_file(file_path, opts \\ []) do
    filter = Keyword.get(opts, :filter, "")
    fields = Keyword.get(opts, :fields, [])

    args =
      ["-r", file_path, "-T", "ek", "-n"] ++
        build_filter_args(filter) ++
        build_fields_args(fields)

    case System.cmd("tshark", args, stderr_to_stdout: true) do
      {output, 0} ->
        output
        |> String.split("\n", trim: true)
        |> Enum.map(&parse_json/1)
        |> Enum.map(&Packet.new/1)

      {error, _} ->
        raise "tshark error: #{error}"
    end
  end

  @doc """
  Starts a live capture on the specified interface with given options.
  Returns a stream of parsed packets.

  ## Example
      iex> capture = ExShark.capture(interface: "any", packet_count: 1)
      iex> is_struct(capture, Stream)
      true
  """
  def capture(opts \\ []) do
    interface = Keyword.get(opts, :interface, "any")
    filter = Keyword.get(opts, :filter, "")
    duration = Keyword.get(opts, :duration)
    packet_count = Keyword.get(opts, :packet_count)
    fields = Keyword.get(opts, :fields, [])

    args =
      ["-i", interface, "-T", "ek", "-l", "-n"] ++
        build_filter_args(filter) ++
        build_duration_args(duration) ++
        build_count_args(packet_count) ++
        build_fields_args(fields)

    Port.open({:spawn_executable, find_tshark()}, [:binary, :exit_status, args: args])
    |> stream_output()
    |> Stream.map(&parse_json/1)
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

  defp parse_json(json_string) do
    case Jason.decode(json_string) do
      {:ok, data} when is_map(data) ->
        case get_in(data, ["layers"]) do
          layers when is_map(layers) and map_size(layers) > 0 -> data
          _ -> %{"layers" => %{}}
        end

      _ ->
        %{"layers" => %{}}
    end
  end
end
