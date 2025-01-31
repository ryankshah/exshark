defmodule ExShark.PacketTest do
  use ExUnit.Case, async: true
  alias ExShark.{Packet, TestHelper}

  setup do
    packet = TestHelper.get_test_packet()
    assert packet, "Failed to get test packet"
    {:ok, packet: packet}
  end

  describe "layer access" do
    test "can access layer using different methods", %{packet: packet} do
      protocol = packet.highest_layer |> String.downcase() |> String.to_atom()

      layer = Packet.get_layer(packet, protocol)
      assert layer, "Failed to get layer by atom"

      layer_by_string = Packet.get_layer(packet, to_string(protocol))
      assert layer_by_string == layer, "Layer access by string failed"

      layer_by_upcase = Packet.get_layer(packet, String.upcase(to_string(protocol)))
      assert layer_by_upcase == layer, "Layer access by uppercase failed"
    end

    test "packet contains layer", %{packet: packet} do
      # Test for any protocol present in the packet
      protocol =
        String.split(packet.frame_info.protocols, ":")
        |> Enum.at(0)
        |> String.upcase()

      assert Packet.has_protocol?(packet, protocol)
      refute Packet.has_protocol?(packet, "INVALID")
    end
  end

  describe "field access" do
    test "ethernet fields", %{packet: packet} do
      # Check for either eth or sll fields
      src = packet[eth: :src] || packet[sll: :src_eth]
      dst = packet[eth: :dst] || packet[sll: :src_eth]

      assert src, "Failed to get source address"
      assert dst, "Failed to get destination address"
      assert Regex.match?(~r/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/, src)
    end

    test "raw mode access", %{packet: packet} do
      protocol = packet.highest_layer |> String.downcase() |> String.to_atom()
      layer = Packet.get_layer(packet, protocol)
      raw_layer = %{layer | raw_mode: true}

      field = Enum.find(Map.keys(layer.fields), &String.contains?(&1, ".raw"))

      if field do
        field_name = field |> String.replace(".raw", "") |> String.to_atom()
        normal_value = Packet.Layer.get_field(layer, field_name)
        raw_value = Packet.Layer.get_field(raw_layer, field_name)
        assert normal_value
        assert raw_value
        assert raw_value != normal_value || is_binary(raw_value)
      end
    end

    test "field access through Access behaviour", %{packet: packet} do
      assert packet[eth: :src] || packet[sll: :src_eth], "Failed to get source address"
    end
  end

  describe "frame info" do
    test "access frame info", %{packet: packet} do
      assert packet.frame_info.protocols
      assert packet.frame_info.number
      assert packet.frame_info.time
    end

    test "frame info contains valid data", %{packet: packet} do
      # Test for ethernet at minimum
      assert String.contains?(packet.frame_info.protocols, ["eth", "sll"])
      assert String.match?(packet.frame_info.number, ~r/^\d+$/)
      assert String.contains?(packet.frame_info.time, [":", "-", "T"])
    end
  end

  describe "packet handling" do
    test "handles nil packet data" do
      packet = Packet.new(nil)
      assert packet.highest_layer == "UNKNOWN"
      assert packet.layers == %{}
      assert packet.frame_info.protocols == ""
    end

    test "handles invalid packet data" do
      packet = Packet.new(%{"invalid" => "data"})
      assert packet.highest_layer == "UNKNOWN"
      assert packet.layers == %{}
      assert packet.frame_info.protocols == ""
    end

    test "handles empty layers" do
      packet = Packet.new(%{"layers" => %{}})
      assert packet.highest_layer == "UNKNOWN"
      assert packet.layers == %{}
      assert packet.frame_info.protocols == ""
    end
  end
end
