defmodule ExShark.LazyCapture do
  @moduledoc """
  Provides lazy loading of packets from a capture file.
  """
  use GenServer
  
  defstruct [:file_path, :filter, :loaded_packets, :total_packets]

  def start_link(file_path, opts \\ []) do
    GenServer.start_link(__MODULE__, {file_path, opts})
  end

  def init({file_path, opts}) do
    # Count total packets without loading them
    total = count_packets(file_path)
    
    {:ok, %__MODULE__{
      file_path: file_path,
      filter: Keyword.get(opts, :filter, ""),
      loaded_packets: %{},
      total_packets: total
    }}
  end

  @doc """
  Gets a specific packet by index, loading it if necessary.
  """
  def get_packet(pid, index) do
    GenServer.call(pid, {:get_packet, index})
  end

  @doc """
  Loads a specified number of packets starting from the current position.
  """
  def load_packets(pid, count) do
    GenServer.call(pid, {:load_packets, count})
  end

  @doc """
  Returns the total number of packets in the capture.
  """
  def total_packets(pid) do
    GenServer.call(pid, :total_packets)
  end

  # Server Callbacks

  def handle_call({:get_packet, index}, _from, state) do
    case Map.get(state.loaded_packets, index) do
      nil ->
        packet = load_single_packet(state.file_path, index)
        new_state = %{state | loaded_packets: Map.put(state.loaded_packets, index, packet)}
        {:reply, packet, new_state}
      packet ->
        {:reply, packet, state}
    end
  end

  def handle_call({:load_packets, count}, _from, state) do
    new_packets = load_packet_range(state.file_path, map_size(state.loaded_packets), count)
    new_loaded = Enum.into(new_packets, state.loaded_packets)
    {:reply, :ok, %{state | loaded_packets: new_loaded}}
  end

  def handle_call(:total_packets, _from, state) do
    {:reply, state.total_packets, state}
  end

  # Private Functions

  defp count_packets(file_path) do
    {output, 0} = System.cmd(find_tshark(), ["-r", file_path, "-c", "1", "-T", "fields"])
    String.to_integer(String.trim(output))
  end

  defp load_single_packet(file_path, index) do
    {output, 0} = System.cmd(find_tshark(), [
      "-r", file_path,
      "-Y", "frame.number == #{index + 1}",
      "-T", "ek",
      "-n"
    ])

    output
    |> String.trim()
    |> Jason.decode!()
    |> ExShark.Packet.new()
  end

  defp load_packet_range(file_path, offset, count) do
    {output, 0} = System.cmd(find_tshark(), [
      "-r", file_path,
      "-Y", "frame.number >= #{offset + 1} && frame.number <= #{offset + count}",
      "-T", "ek",
      "-n"
    ])
    
    output
    |> String.split("\n", trim: true)
    |> Enum.map(&Jason.decode!/1)
    |> Enum.map(&ExShark.Packet.new/1)
    |> Enum.with_index(offset)
    |> Enum.into(%{})
  end

  defp find_tshark do
    System.find_executable("tshark") ||
      raise "tshark executable not found in PATH"
  end
end