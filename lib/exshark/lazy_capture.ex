defmodule ExShark.LazyCapture do
  @moduledoc """
  Provides lazy loading of PCAP files for memory-efficient packet processing.
  Loads and analyzes packets on-demand rather than loading entire capture
  files into memory at once.
  """

  use GenServer

  defstruct [:file_path, :filter, :loaded_packets, :total_packets]

  def start_link(file_path, opts \\ []) do
    GenServer.start_link(__MODULE__, {file_path, opts})
  end

  def init({file_path, opts}) do
    case count_packets(file_path, Keyword.get(opts, :filter, "")) do
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
    with true <- valid_index?(index, state.total_packets),
         {:ok, packet} <- get_or_load_packet(index, state) do
      {:reply, packet, update_loaded_packets(state, index, packet)}
    else
      false -> {:reply, {:error, "Index out of range"}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call({:load_packets, count}, _from, state) do
    case load_packet_range(state.file_path, map_size(state.loaded_packets), count, state.filter) do
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

  defp valid_index?(index, total), do: index >= 0 && index < total

  defp get_or_load_packet(index, state) do
    case Map.get(state.loaded_packets, index) do
      nil -> load_single_packet(state.file_path, index, state.filter)
      packet -> {:ok, packet}
    end
  end

  defp update_loaded_packets(state, index, packet) do
    %{state | loaded_packets: Map.put(state.loaded_packets, index, packet)}
  end

  defp load_single_packet(file_path, index, filter) do
    filter_args = if filter && filter != "", do: ["-Y", filter], else: []
    base_args = ["-r", file_path, "-T", "ek", "-n", "-c", "#{index + 1}"]
    args = base_args ++ filter_args

    with {output, 0} <- System.cmd("tshark", args),
         packets <- parse_packets(output),
         packet when not is_nil(packet) <- Enum.at(packets, index) do
      {:ok, packet}
    else
      {error, _} -> {:error, "tshark error: #{error}"}
      [] -> {:error, "No packets found"}
      nil -> {:error, "Invalid packet index"}
      _ -> {:error, "Failed to parse packet"}
    end
  end

  defp parse_packets(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.map(&parse_line/1)
    |> Enum.filter(&valid_packet?/1)
  end

  defp parse_line(line) do
    case Jason.decode(line) do
      {:ok, json} -> ExShark.Packet.new(json)
      _ -> nil
    end
  end

  defp valid_packet?(%ExShark.Packet{layers: layers}) when map_size(layers) > 0, do: true
  defp valid_packet?(_), do: false

  defp count_packets(file_path, filter) do
    filter_args = if filter && filter != "", do: ["-Y", filter], else: []
    base_args = ["-r", file_path, "-T", "fields", "-e", "frame.number"]
    args = base_args ++ filter_args

    case System.cmd("tshark", args) do
      {output, 0} ->
        count =
          output
          |> String.split("\n", trim: true)
          |> length()

        {:ok, count}

      {error, _} ->
        {:error, "tshark error: #{error}"}
    end
  end

  defp load_packet_range(file_path, offset, count, filter) do
    filter_args = if filter && filter != "", do: ["-Y", filter], else: []
    base_args = ["-r", file_path, "-T", "ek", "-n"]
    args = base_args ++ filter_args

    case System.cmd("tshark", args) do
      {output, 0} ->
        packets =
          output
          |> String.split("\n", trim: true)
          |> Enum.map(&parse_line/1)
          |> Enum.filter(&valid_packet?/1)
          |> Enum.slice(offset, count)
          |> Enum.with_index(offset)
          |> Enum.into(%{})

        {:ok, packets}

      {error, _} ->
        {:error, "tshark error: #{error}"}
    end
  end
end
