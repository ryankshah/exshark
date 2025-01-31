defmodule ExShark.Packet do
  @moduledoc """
  Represents a parsed network packet with convenient field access.
  """

  alias ExShark.Packet.Layer

  @behaviour Access

  # Known protocol ordering from lowest to highest layer
  @protocol_order ~w(eth sll ip tcp udp icmp dns http tls)

  # Protocol aliases for compatibility
  @protocol_aliases %{
    "ethernet" => "eth",
    "ether" => "eth",
    "ipv4" => "ip",
    "ipv6" => "ip"
  }

  @impl Access
  def fetch(packet, key)

  def fetch(packet, [{protocol, field}]) do
    case get_protocol_field(packet, protocol, field) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  def fetch(packet, {protocol, field}) when is_atom(protocol) and is_atom(field) do
    case get_protocol_field(packet, protocol, field) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  def fetch(_packet, _), do: :error

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
          length: 0,
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
    protocols_list = get_protocols_list(packet)

    cond do
      protocol == :eth -> has_ethernet?(packet)
      true -> protocol in protocols_list || Map.has_key?(packet.layers, protocol)
    end
  end

  @doc """
  Gets a protocol field value from the packet.
  """
  def get_protocol_field(packet, protocol, field) do
    protocol = normalize_protocol_name(protocol)

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

    cond do
      protocol == :eth && Map.has_key?(packet.layers, :sll) ->
        sll_layer = Map.get(packet.layers, :sll)
        Layer.new(:eth, convert_sll_to_eth(sll_layer))

      true ->
        case Map.get(packet.layers, protocol) do
          nil -> nil
          layer_data -> Layer.new(protocol, layer_data)
        end
    end
  end

  # Private Functions

  defp has_ethernet?(packet) do
    Map.has_key?(packet.layers, :eth) || Map.has_key?(packet.layers, :sll)
  end

  defp convert_sll_to_eth(sll_data) do
    %{
      "eth.src" => Map.get(sll_data, "sll_sll_src_eth"),
      "eth.dst" => Map.get(sll_data, "sll_sll_src_eth"),
      "eth.type" => Map.get(sll_data, "sll_sll_etype")
    }
  end

  defp normalize_protocol_name(protocol) when is_atom(protocol), do: protocol

  defp normalize_protocol_name(protocol) when is_binary(protocol) do
    protocol
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9]/, "")
    |> apply_protocol_alias()
    |> String.to_atom()
  end

  defp apply_protocol_alias(protocol) do
    Map.get(@protocol_aliases, protocol, protocol)
  end

  defp normalize_packet(nil), do: nil

  defp normalize_packet(%{} = raw_packet) do
    case raw_packet do
      %{"layers" => layers} when is_map(layers) and map_size(layers) > 0 -> raw_packet
      _ -> nil
    end
  end

  defp normalize_packet(_), do: nil

  defp build_packet(packet_data) do
    layers =
      case get_in(packet_data, ["layers"]) do
        layers when is_map(layers) and map_size(layers) > 0 ->
          Map.new(layers, fn {k, v} ->
            protocol = String.downcase(k) |> String.to_atom()
            {protocol, normalize_layer_data(v)}
          end)

        _ ->
          %{}
      end

    frame_info = build_frame_info(packet_data)
    highest = determine_highest_layer(layers, frame_info.protocols)
    length = get_packet_length(packet_data)

    %__MODULE__{
      layers: layers,
      length: length,
      highest_layer: highest,
      summary_fields: get_summary_fields(packet_data),
      frame_info: frame_info,
      raw_mode: false
    }
  end

  defp normalize_layer_data(data) when is_map(data) do
    Map.new(data, fn {k, v} -> {String.replace(k, "_", "."), v} end)
  end

  defp normalize_layer_data(data), do: data

  defp get_packet_length(packet_data) do
    case get_in(packet_data, ["layers", "frame", "frame.len"]) do
      len when is_binary(len) -> String.to_integer(len)
      _ -> 0
    end
  end

  defp build_frame_info(packet_data) do
    frame_layer = get_in(packet_data, ["layers", "frame"]) || %{}

    protocols =
      case get_in(frame_layer, ["frame.protocols"]) do
        protocols when is_binary(protocols) ->
          protocols
          |> String.downcase()
          |> String.replace(~r/\s+/, "")

        _ ->
          get_in(frame_layer, ["frame_frame_protocols"]) || ""
      end

    %FrameInfo{
      protocols: protocols,
      number: get_frame_number(frame_layer),
      time: get_frame_time(frame_layer)
    }
  end

  defp get_frame_number(frame_layer) do
    get_in(frame_layer, ["frame.number"]) ||
      get_in(frame_layer, ["frame_frame_number"]) ||
      ""
  end

  defp get_frame_time(frame_layer) do
    get_in(frame_layer, ["frame.time"]) ||
      get_in(frame_layer, ["frame_frame_time"]) ||
      ""
  end

  defp get_summary_fields(%{"layers" => layers}) when is_map(layers) do
    Map.take(layers, ["frame.time", "frame.len", "frame.protocols"])
  end

  defp get_summary_fields(_), do: %{}

  defp get_protocols_list(packet) do
    packet.frame_info.protocols
    |> String.downcase()
    |> String.split(":")
    |> Enum.map(&String.trim/1)
    |> Enum.map(&String.to_atom/1)
  end

  defp determine_highest_layer(layers, protocols_str) do
    available_protocols =
      if protocols_str != "" do
        protocols_str
        |> String.downcase()
        |> String.split(":")
        |> Enum.map(&String.trim/1)
      else
        Map.keys(layers) |> Enum.map(&to_string/1)
      end
      |> Enum.filter(&(&1 in @protocol_order))
      |> Enum.sort_by(&Enum.find_index(@protocol_order, fn x -> x == &1 end))

    case List.last(available_protocols) do
      nil -> "UNKNOWN"
      proto -> String.upcase(proto)
    end
  end
end
