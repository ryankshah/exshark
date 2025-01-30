defmodule ExShark.PacketTest do
  @moduledoc """
  Tests for the ExShark.Packet module and its submodules.
  """

  use ExUnit.Case, async: true
  alias ExShark.{Packet, TestHelper}

  setup do
    test_packets = ExShark.read_file(TestHelper.test_pcap_path())
    # Get the first ICMP packet for testing
    icmp_packet = Enum.find(test_packets, &(&1.highest_layer == "ICMP"))
    {:ok, packets: test_packets, icmp_packet: icmp_packet || hd(test_packets)}
  end

  describe "layer access" do
    test "can access layer using different methods", %{icmp_packet: packet} do
      layer_by_atom = Packet.get_layer(packet, :icmp)
      layer_by_string = Packet.get_layer(packet, "icmp")
      layer_by_upcase = Packet.get_layer(packet, "ICMP")

      # All methods should return equivalent layers
      refute is_nil(layer_by_atom)
      assert layer_by_atom == layer_by_string
      assert layer_by_string == layer_by_upcase
      assert String.upcase(layer_by_atom.name) == "ICMP"
    end

    test "packet contains layer", %{icmp_packet: packet} do
      assert Packet.has_protocol?(packet, "ICMP")
      refute Packet.has_protocol?(packet, "HTTP")
    end
  end

  describe "field access" do
    test "ethernet fields", %{packets: [packet | _]} do
      assert packet[eth: :src]
      assert packet[eth: :dst]
    end

    test "raw mode access", %{icmp_packet: packet} do
      # Get the layer and compare normal vs raw mode
      ip_layer = Packet.get_layer(packet, :ip)
      raw_ip_layer = %{ip_layer | raw_mode: true}

      normal_src = Packet.Layer.get_field(ip_layer, :src)
      raw_src = Packet.Layer.get_field(raw_ip_layer, :src)

      assert normal_src
      assert raw_src
      # Raw value might be the same if no raw field is available
      assert raw_src == (Map.get(ip_layer.fields, "ip.src.raw") || normal_src)
    end

    test "icmp response time", %{icmp_packet: packet} do
      resptime = packet[icmp: :resptime]

      if resptime do
        normalized = String.replace(resptime, ",", ".")
        assert String.to_float(normalized) > 0
      end
    end
  end

  describe "frame info" do
    test "access frame info", %{icmp_packet: packet} do
      assert packet.frame_info.protocols
      assert packet.frame_info.number
      assert packet.frame_info.time
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
