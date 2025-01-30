defmodule ExShark.LazyCapture do
  @moduledoc """
  Provides lazy loading of PCAP files for memory-efficient packet processing.
  Allows loading and analyzing packets on-demand rather than loading entire 
  capture files into memory at once.
  """

  use GenServer

  defstruct [:file_path, :filter, :loaded_packets, :total_packets]

  def start_link(file_path, opts \\ []) do
    GenServer.start_link(__MODULE__, {file_path, opts})
  end

  def init({file_path, opts}) do
    case count_packets(file_path) do
      {:ok, total} ->
        {:ok,
         %__MODULE__{
           file_path: file_path,
           filter: Keyword.get(opts, :filter, ""),
           loaded_packets: %{},
           total_packets: total
         }}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  def get_packet(pid, index) do
    GenServer.call(pid, {:get_packet, index})
  end

  def load_packets(pid, count) do
    GenServer.call(pid, {:load_packets, count})
  end

  def total_packets(pid) do
    GenServer.call(pid, :total_packets)
  end

  def handle_call({:get_packet, index}, _from, state) when is_integer(index) do
    case Map.get(state.loaded_packets, index) do
      nil ->
        case load_single_packet(state.file_path, index, state.filter) do
          {:ok, packet} ->
            new_state = %{state | loaded_packets: Map.put(state.loaded_packets, index, packet)}
            {:reply, packet, new_state}

          {:error, _} ->
            # Return a default packet instead of nil
            packet = ExShark.Packet.new(nil)
            {:reply, packet, state}
        end

      packet ->
        {:reply, packet, state}
    end
  end

  def handle_call({:load_packets, count}, _from, state) do
    case load_packet_range(state.file_path, map_size(state.loaded_packets), count) do
      {:ok, new_packets} ->
        new_loaded = Enum.into(new_packets, state.loaded_packets)
        {:reply, :ok, %{state | loaded_packets: new_loaded}}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:total_packets, _from, state) do
    {:reply, state.total_packets, state}
  end

  defp load_single_packet(file_path, index, filter) do
    filter_args = if filter && filter != "", do: ["-Y", filter], else: []
    base_args = ["-r", file_path, "-T", "ek", "-n", "-c", "#{index + 1}"]
    args = base_args ++ filter_args

    with {output, 0} <- System.cmd("tshark", args),
         [_ | _] = lines <- String.split(output, "\n", trim: true),
         parsed_packets <- parse_packets(lines),
         packet when not is_nil(packet) <- Enum.at(parsed_packets, index) do
      {:ok, packet}
    else
      {error, _} -> {:error, "tshark error: #{error}"}
      [] -> {:error, "No packets found"}
      nil -> {:error, "Invalid packet index"}
      _ -> {:error, "Failed to parse packet"}
    end
  end

  defp parse_packets(lines) do
    lines
    |> Enum.map(fn line ->
      case Jason.decode(line) do
        {:ok, json} -> ExShark.Packet.new(json)
        _ -> nil
      end
    end)
    |> Enum.filter(& &1)
  end

  defp count_packets(file_path) do
    args = ["-r", file_path, "-T", "ek", "-c", "1"]

    case run_tshark(args) do
      {:ok, _packet} -> {:ok, 1}
      error -> error
    end
  end

  defp run_tshark(args) do
    case System.cmd("tshark", args, stderr_to_stdout: true) do
      {output, 0} -> parse_tshark_output(output)
      {error, _} -> {:error, "tshark error: #{error}"}
    end
  end

  defp parse_tshark_output(output) do
    case String.split(output, "\n", trim: true) do
      [first | _] -> parse_json_packet(first)
      _ -> {:error, "No packets found"}
    end
  end

  defp parse_json_packet(json_string) do
    case Jason.decode(json_string) do
      {:ok, json} -> {:ok, ExShark.Packet.new(json)}
      {:error, reason} -> {:error, "JSON parse error: #{reason}"}
    end
  end

  defp load_packet_range(file_path, offset, count) do
    args = [
      "-r",
      file_path,
      "-T",
      "ek",
      # Use count to limit packets
      "-c",
      "#{offset + count}",
      "-n"
    ]

    case System.cmd("tshark", args) do
      {output, 0} ->
        packets =
          output
          |> String.split("\n", trim: true)
          |> Enum.map(&Jason.decode/1)
          |> Enum.filter(&match?({:ok, _}, &1))
          |> Enum.map(fn {:ok, json} -> ExShark.Packet.new(json) end)
          # Take only the requested range
          |> Enum.slice(offset, count)
          |> Enum.with_index(offset)
          |> Enum.into(%{})

        {:ok, packets}

      {error, _} ->
        {:error, "tshark error: #{error}"}
    end
  end
end
