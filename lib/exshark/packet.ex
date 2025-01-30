defmodule ExShark.Packet do
  @moduledoc """
  Represents a parsed network packet with convenient field access.
  """

  @behaviour Access

  @impl Access
  def fetch(packet, [{protocol, field}]), do: do_fetch(packet, protocol, field)

  def fetch(packet, {protocol, field}) when is_atom(protocol) and is_atom(field),
    do: do_fetch(packet, protocol, field)

  def fetch(_packet, _), do: :error

  defp do_fetch(packet, protocol, field) do
    if has_protocol?(packet, protocol) do
      case get_protocol_field(packet, protocol, field) do
        nil -> :error
        value -> {:ok, value}
      end
    else
      :error
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

  @doc """
  Checks if the packet contains a specific protocol.
  """
  def has_protocol?(packet, protocol) do
    protocol = normalize_protocol_name(protocol)

    protocols_list =
      packet.frame_info.protocols
      |> String.downcase()
      |> String.split(":")
      |> Enum.map(&String.trim/1)

    proto_str = to_string(protocol)
    proto_str in protocols_list || Map.has_key?(packet.layers, protocol)
  end

  @doc """
  Gets a protocol field value from the packet.
  """
  def get_protocol_field(packet, protocol, field) do
    case get_layer(packet, protocol) do
      nil -> nil
      layer -> Layer.get_field(layer, field)
    end
  end

  @doc """
  Gets a protocol layer from the packet.
  """
  def get_layer(packet, protocol) do
    protocol = normalize_protocol_name(protocol)

    case Map.get(packet.layers, protocol) do
      nil -> nil
      layer_data -> Layer.new(protocol, layer_data)
    end
  end

  # Private Functions

  defp normalize_protocol_name(protocol) when is_atom(protocol), do: protocol

  defp normalize_protocol_name(protocol) when is_binary(protocol) do
    protocol
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]/, "")
    |> String.to_atom()
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
          Map.new(layers, fn {k, v} ->
            protocol = String.to_atom(String.downcase(k))
            {protocol, v}
          end)

        _ ->
          %{}
      end

    frame_info = build_frame_info(packet_data)
    # Removed second parameter
    highest = determine_highest_layer(layers)

    %__MODULE__{
      layers: layers,
      length: get_in(packet_data, ["layers", "frame", "frame.len"]) || "0",
      highest_layer: highest,
      summary_fields: get_summary_fields(packet_data),
      frame_info: frame_info,
      raw_mode: false
    }
  end

  defp build_frame_info(packet_data) do
    frame_layer = get_in(packet_data, ["layers", "frame"]) || %{}
    protocols = get_in(frame_layer, ["frame.protocols"]) || ""
    number = get_in(frame_layer, ["frame.number"]) || ""
    time = get_in(frame_layer, ["frame.time"]) || ""

    %FrameInfo{
      protocols: protocols,
      number: number,
      time: time
    }
  end

  defp get_summary_fields(%{"layers" => layers}) when is_map(layers) do
    Map.take(layers, ["frame.time", "frame.len", "frame.protocols"])
  end

  defp get_summary_fields(_), do: %{}

  defp determine_highest_layer(layers) do
    protocol_order = ~w(eth ip tcp udp dns icmp http tls)

    highest =
      layers
      |> Map.keys()
      |> Enum.map(&to_string/1)
      |> Enum.filter(&(&1 in protocol_order))
      |> Enum.sort_by(fn proto ->
        Enum.find_index(protocol_order, &(&1 == proto)) || -1
      end)
      |> List.last()

    if highest, do: String.upcase(highest), else: "UNKNOWN"
  end
end
