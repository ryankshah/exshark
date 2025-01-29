defmodule ExShark.PacketTest do
  use ExUnit.Case, async: true
  alias ExShark.Packet

  setup do
    packets = ExShark.read_file(ExShark.TestHelper.test_pcap_path())
    icmp_packet = Enum.at(packets, 7)
    {:ok, packets: packets, icmp_packet: icmp_packet}
  end

  describe "layer access" do
    test "can access layer using different methods", %{icmp_packet: packet} do
      access_methods = [
        &Packet.get_layer(&1, :icmp),
        &Packet.get_layer(&1, "icmp"),
        &Packet.get_layer(&1, "ICMP")
      ]

      Enum.each(access_methods, fn access_func ->
        layer = access_func.(packet)
        assert String.upcase(layer.name) == "ICMP"
        
        data = layer.data
        |> Base.decode16!(case: :lower)
        assert data == "abcdefghijklmnopqrstuvwabcdefghi"
      end)
    end

    test "packet contains layer", %{icmp_packet: packet} do
      assert Packet.has_protocol?(packet, "ICMP")
    end
  end

  describe "field access" do
    test "ethernet fields", %{packets: packets} do
      packet = Enum.at(packets, 0)
      test_values = {packet[eth: :src], packet[eth: :dst]}
      known_values = {"00:00:bb:10:20:10", "00:00:bb:02:04:01"}
      assert test_values == known_values
    end

    test "raw mode access", %{icmp_packet: packet} do
      original_src = packet[ip: :src]
      
      ip_layer = Packet.get_layer(packet, :ip)
      raw_ip_layer = %{ip_layer | raw_mode: true}
      
      raw_src = Packet.Layer.get_field(raw_ip_layer, :src)
      assert raw_src != original_src
    end

    test "icmp response time", %{packets: packets} do
      packet = Enum.at(packets, 11)
      resptime = packet[icmp: :resptime]
                 |> String.replace(",", ".")
      assert resptime == "1.667"
    end
  end

  describe "frame info" do
    test "access frame info", %{icmp_packet: packet} do
      expected_protocols = MapSet.new(["eth:ip:icmp:data", "eth:ethertype:ip:icmp:data"])
      actual_protocols = MapSet.new([packet.frame_info.protocols])
      
      assert MapSet.subset?(actual_protocols, expected_protocols)
      assert packet.frame_info.number == "8"
    end
  end
end