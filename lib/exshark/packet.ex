defmodule ExShark.Packet do
  @moduledoc """
  Represents a parsed network packet with convenient field access.
  """

  @behaviour Access

  # Implement Access behaviour
  @impl Access
  def fetch(packet, {protocol, field}) when is_atom(protocol) and is_atom(field) do
    {proto, fld} =
      case protocol do
        [p, f] -> {p, f}
        _ -> {protocol, field}
      end

    case get_protocol_field(packet, proto, fld) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  def get(packet, key, default \\ nil) do
    case fetch(packet, key) do
      {:ok, value} -> value
      :error -> default
    end
  end

  @impl Access
  def get_and_update(_packet, _key, _fun), do: raise("Not implemented")

  @impl Access
  def pop(_packet, _key), do: raise("Not implemented")

  defmodule Layer do
    @moduledoc """
    Represents a protocol layer with support for raw values.
    """
    defstruct [:name, :fields, :data, :raw_mode]

    def new(name, fields, data \\ nil) do
      %__MODULE__{
        name: name,
        fields: fields || %{},
        data: data,
        raw_mode: false
      }
    end

    def get_field(layer, field) do
      value = Map.get(layer.fields, "#{layer.name}.#{field}")
      raw_value = Map.get(layer.fields, "#{layer.name}.#{field}.raw")

      if layer.raw_mode && raw_value do
        raw_value
      else
        value
      end
    end
  end

  defmodule FrameInfo do
    @moduledoc """
    Represents frame-level information for a packet.
    """
    defstruct [:protocols, :number, :time]
  end

  defstruct [:layers, :length, :highest_layer, :summary_fields, :frame_info, :raw_mode]

  @doc """
  Creates a new Packet struct from raw tshark JSON output.
  """
  def new(raw_packet) do
    case normalize_packet(raw_packet) do
      nil ->
        %__MODULE__{
          layers: %{},
          length: "0",
          highest_layer: "UNKNOWN",
          summary_fields: %{},
          frame_info: %FrameInfo{protocols: "", number: "", time: ""},
          raw_mode: false
        }

      packet_data ->
        build_packet(packet_data)
    end
  end

  defp normalize_packet(nil), do: nil

  defp normalize_packet(%{} = raw_packet) do
    case raw_packet do
      %{"layers" => layers} when is_map(layers) -> raw_packet
      _ -> nil
    end
  end

  defp normalize_packet(_), do: nil

  defp build_packet(packet_data) do
    layers =
      case get_in(packet_data, ["layers"]) do
        layers when is_map(layers) and map_size(layers) > 0 ->
          # Convert protocol names to atoms and preserve layer data
          Map.new(layers, fn {k, v} ->
            protocol = String.to_atom(k)
            {protocol, v}
          end)

        _ ->
          %{}
      end

    highest = determine_highest_layer(layers)

    %__MODULE__{
      layers: layers,
      length: get_in(packet_data, ["layers", "frame", "frame.len"]) || "0",
      highest_layer: highest,
      summary_fields: get_summary_fields(packet_data),
      frame_info: build_frame_info(packet_data),
      raw_mode: false
    }
  end

  defp get_summary_fields(%{"layers" => layers}) when is_map(layers) do
    Map.take(layers, ["frame.time", "frame.len", "frame.protocols"])
  end

  defp get_summary_fields(_), do: %{}

  defp build_frame_info(raw_packet) do
    frame_layer = get_in(raw_packet, ["layers", "frame"]) || %{}

    %FrameInfo{
      protocols: Map.get(frame_layer, "frame.protocols", ""),
      number: Map.get(frame_layer, "frame.number", ""),
      time: Map.get(frame_layer, "frame.time", "")
    }
  end

  @doc """
  Gets a protocol layer from the packet.
  """
  def get_layer(packet, protocol) do
    protocol = normalize_protocol_name(protocol)

    case Map.get(packet.layers, protocol) do
      nil ->
        nil

      layer_data ->
        data = Map.get(layer_data, "#{protocol}.data")
        Layer.new(protocol, layer_data, data)
    end
  end

  @doc """
  Gets a protocol field value from the packet.
  """
  def get_protocol_field(packet, protocol, field) do
    case Map.get(packet.layers, protocol) do
      nil ->
        nil

      layer_data ->
        layer = Layer.new(protocol, layer_data)
        Layer.get_field(layer, field)
    end
  end

  @doc """
  Checks if the packet contains a specific protocol.
  """
  def has_protocol?(packet, protocol) do
    protocol = normalize_protocol_name(protocol)
    Map.has_key?(packet.layers, protocol)
  end

  # Private Functions

  defp normalize_protocol_name(protocol) when is_atom(protocol), do: protocol

  defp normalize_protocol_name(protocol) when is_binary(protocol),
    do: String.downcase(protocol) |> String.to_atom()

  defp determine_highest_layer(layers) when map_size(layers) > 0 do
    protocol_order = ~w(eth ip tcp udp dns icmp http)

    highest =
      layers
      |> Map.keys()
      |> Enum.map(&to_string/1)
      |> Enum.filter(&(&1 in protocol_order))
      |> Enum.sort_by(&Enum.find_index(protocol_order, fn x -> x == &1 end))
      |> List.last()

    if highest, do: String.upcase(highest), else: "UNKNOWN"
  end

  defp determine_highest_layer(_), do: "UNKNOWN"
end
