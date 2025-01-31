defmodule ExShark do
  @moduledoc """
  ExShark is an Elixir wrapper for tshark (Wireshark's command-line interface) that enables
  packet capture and analysis using Wireshark's powerful dissectors.
  """

  alias ExShark.Packet

  @default_timeout 5000

  @doc """
  Reads packets from a pcap file and returns them as a list.
  """
  def read_file(file_path, opts \\ []) when is_list(opts) do
    filter = opts[:filter] || ""
    fields = opts[:fields] || []

    args =
      ["-r", file_path, "-T", "ek", "-n"] ++
        build_filter_args(filter) ++
        build_fields_args(fields)

    case System.cmd("tshark", args, stderr_to_stdout: true) do
      {output, 0} ->
        output
        |> String.split("\n", trim: true)
        |> Stream.map(&parse_json/1)
        |> Stream.map(&Packet.new/1)
        |> Stream.filter(&valid_packet?/1)
        |> Enum.to_list()

      {error, _} ->
        raise "tshark error: #{error}"
    end
  end

  @doc """
  Starts a live capture on the specified interface with given options.
  """
  def capture(opts \\ []) do
    opts = normalize_capture_options(opts)

    if String.ends_with?(opts.interface, ".pcap") do
      simulate_capture_with_pcap(opts)
    else
      live_capture(opts)
    end
  end

  defp simulate_capture_with_pcap(opts) do
    read_opts = [
      filter: opts.filter,
      fields: opts.fields
    ]

    packets = read_file(opts.interface, read_opts)

    if opts.packet_count, do: Enum.take(packets, opts.packet_count), else: packets
  end

  defp live_capture(opts) do
    port = start_capture(opts)

    maybe_generate_traffic(opts.interface)

    create_packet_stream(port)
    |> Stream.filter(&valid_packet?/1)
    |> add_packet_limit(opts.packet_count)
  end

  # Private Functions

  defp normalize_capture_options(opts) do
    %{
      interface: Keyword.get(opts, :interface, "any"),
      filter: Keyword.get(opts, :filter, ""),
      duration: Keyword.get(opts, :duration),
      packet_count: Keyword.get(opts, :packet_count),
      fields: Keyword.get(opts, :fields, []),
      timeout: Keyword.get(opts, :timeout, @default_timeout)
    }
  end

  defp start_capture(opts) do
    args = build_capture_args(opts)

    Port.open({:spawn_executable, find_tshark()}, [
      :binary,
      :exit_status,
      {:line, 16_384},
      args: args
    ])
  end

  defp build_capture_args(opts) do
    ["-i", opts.interface, "-T", "ek", "-l", "-n"] ++
      build_filter_args(opts.filter) ++
      build_duration_args(opts.duration) ++
      build_count_args(opts.packet_count) ++
      build_fields_args(opts.fields)
  end

  defp create_packet_stream(port) do
    Stream.resource(
      fn -> {port, []} end,
      &handle_packet_stream/1,
      &cleanup_capture/1
    )
  end

  defp handle_packet_stream({port, []}) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        handle_packet_data(line)

      {^port, {:exit_status, _}} ->
        {:halt, port}

      _other ->
        {[], {port, []}}
    after
      @default_timeout -> {:halt, port}
    end
  end

  defp handle_packet_stream({port, [], true}) do
    {:halt, port}
  end

  defp handle_packet_data(line) do
    case parse_json(line) do
      packet when is_map(packet) ->
        {[Packet.new(packet)], {nil, []}}

      _ ->
        {[], {nil, []}}
    end
  end

  defp cleanup_capture(port) when is_port(port) do
    # try do
    Port.close(port)
    # catch
    #   :error, :badarg -> :ok
    # end
  end

  defp cleanup_capture(_), do: :ok

  defp maybe_generate_traffic(interface) do
    if should_generate_traffic?(interface) do
      generate_loopback_traffic()
      Process.sleep(200)
    end
  end

  defp should_generate_traffic?(interface) do
    loopback_interfaces = [
      "lo",
      "lo0",
      "\\Device\\NPF_Loopback",
      "Loopback: lo",
      "Loopback"
    ]

    Enum.any?(loopback_interfaces, &String.contains?(interface, &1))
  end

  defp generate_loopback_traffic do
    spawn_ping_command(get_ping_args())
  end

  defp spawn_ping_command(args) do
    Task.start(fn ->
      System.cmd(get_ping_command(), args, stderr_to_stdout: true)
    end)
  end

  defp get_ping_command do
    case :os.type() do
      {:win32, _} -> "ping"
      _ -> "/bin/ping"
    end
  end

  defp get_ping_args do
    ping_count = "3"

    case :os.type() do
      {:win32, _} -> ["-n", ping_count, "127.0.0.1"]
      {:unix, :darwin} -> ["-c", ping_count, "127.0.0.1"]
      _ -> ["-c", ping_count, "-i", "0.1", "127.0.0.1"]
    end
  end

  defp add_packet_limit(stream, nil), do: stream

  defp add_packet_limit(stream, count) when is_integer(count) and count > 0 do
    Stream.take(stream, count)
  end

  defp find_tshark do
    case System.find_executable("tshark") do
      nil -> raise "tshark executable not found in PATH"
      path -> path
    end
  end

  defp build_filter_args(""), do: []
  defp build_filter_args(filter), do: ["-Y", filter]

  defp build_duration_args(nil), do: []
  defp build_duration_args(duration), do: ["-a", "duration:#{duration}"]

  defp build_count_args(nil), do: []
  defp build_count_args(count), do: ["-c", "#{count}"]

  defp build_fields_args([]), do: []
  defp build_fields_args(fields), do: Enum.flat_map(fields, &["-e", &1])

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

  defp valid_packet?(%Packet{highest_layer: "UNKNOWN"}), do: false
  defp valid_packet?(%Packet{layers: layers}) when map_size(layers) > 0, do: true
  defp valid_packet?(_), do: false
end
