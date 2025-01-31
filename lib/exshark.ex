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
    interface = Keyword.get(opts, :interface, "any")
    filter = Keyword.get(opts, :filter, "")
    duration = Keyword.get(opts, :duration)
    packet_count = Keyword.get(opts, :packet_count)
    fields = Keyword.get(opts, :fields, [])
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    args =
      ["-i", interface, "-T", "ek", "-l", "-n"] ++
        build_filter_args(filter) ++
        build_duration_args(duration) ++
        build_count_args(packet_count) ++
        build_fields_args(fields)

    port =
      Port.open({:spawn_executable, find_tshark()}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: args
      ])

    # Start traffic generation before capture starts
    if should_generate_traffic?(interface) do
      generate_loopback_traffic()
      # Give some time for traffic to start flowing
      Process.sleep(200)
    end

    stream =
      Stream.resource(
        # Added closed flag
        fn -> {port, [], false} end,
        fn
          {port, [], false} ->
            receive do
              {^port, {:data, {:eol, line}}} ->
                case parse_json(line) do
                  packet when is_map(packet) ->
                    {[Packet.new(packet)], {port, [], false}}

                  _ ->
                    {[], {port, [], false}}
                end

              {^port, {:exit_status, _}} ->
                {:halt, {port, [], true}}

              other ->
                IO.inspect(other, label: "Unexpected message")
                {[], {port, [], false}}
            after
              timeout -> {:halt, {port, [], true}}
            end

          {port, [], true} ->
            {:halt, port}
        end,
        fn
          port when is_port(port) ->
            try do
              if should_generate_traffic?(interface) do
                # Give time for final packets to arrive
                Process.sleep(100)
              end

              Port.close(port)
            catch
              :error, :badarg -> :ok
            end

          _ ->
            :ok
        end
      )

    filtered_stream =
      stream
      |> Stream.filter(&valid_packet?/1)
      |> add_packet_limit(packet_count)

    # For loopback interfaces, ensure we have traffic before returning
    if should_generate_traffic?(interface) do
      Enum.reduce_while(filtered_stream, [], fn packet, acc ->
        if length(acc) < (packet_count || 1) do
          {:cont, [packet | acc]}
        else
          {:halt, acc}
        end
      end)
      |> case do
        [] -> generate_loopback_traffic()
        packets -> packets
      end
    end

    filtered_stream
  end

  defp add_packet_limit(stream, nil), do: stream

  defp add_packet_limit(stream, count) when is_integer(count) and count > 0 do
    stream |> Stream.take(count)
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
    ping_count = "3"

    ping_args =
      case :os.type() do
        {:win32, _} -> ["-n", ping_count, "127.0.0.1"]
        {:unix, :darwin} -> ["-c", ping_count, "127.0.0.1"]
        _ -> ["-c", ping_count, "-i", "0.1", "127.0.0.1"]
      end

    Task.start(fn ->
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
