defmodule ExShark.Packet do
  @moduledoc """
  Represents a parsed network packet with convenient field access and layer information.
  """

  defmodule Layer do
    @moduledoc """
    Represents a protocol layer with support for raw values.
    """
    defstruct [:name, :fields, :data, :raw_mode]

    def new(name, fields, data \\ nil) do
      %__MODULE__{
        name: name,
        fields: fields,
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
  def new(raw_packet, summary_only \\ false) do
    layers =
      raw_packet
      |> Map.get("layers", %{})
      |> Map.new(fn {k, v} -> {String.to_atom(k), v} end)

    length = get_in(raw_packet, ["layers", "frame", "frame.len"])
    highest_layer = determine_highest_layer(layers)
    frame_info = extract_frame_info(raw_packet)

    %__MODULE__{
      layers: if(summary_only, do: nil, else: layers),
      length: length,
      highest_layer: highest_layer,
      summary_fields: extract_summary_fields(raw_packet),
      frame_info: frame_info,
      raw_mode: false
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

  @doc """
  Gets a field value from a specific protocol.

  ## Example
      iex> packet |> ExShark.Packet.get_field({:eth, :src})
      "00:11:22:33:44:55"
  """
  def get_field(packet, {protocol, field} = key) when is_atom(protocol) and is_atom(field) do
    ExShark.PacketAccess.get(packet, key)
  end

  # Private Functions

  defp normalize_protocol_name(protocol) when is_atom(protocol), do: protocol

  defp normalize_protocol_name(protocol) when is_binary(protocol),
    do: String.downcase(protocol) |> String.to_atom()

  defp determine_highest_layer(layers) when is_map(layers) do
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

  defp extract_frame_info(raw_packet) do
    frame_layer = get_in(raw_packet, ["layers", "frame"]) || %{}

    %FrameInfo{
      protocols: Map.get(frame_layer, "frame.protocols", ""),
      number: Map.get(frame_layer, "frame.number", ""),
      time: Map.get(frame_layer, "frame.time", "")
    }
  end

  defp extract_summary_fields(raw_packet) do
    Map.take(raw_packet["layers"], ["frame.time", "frame.len", "frame.protocols"])
  end
end
