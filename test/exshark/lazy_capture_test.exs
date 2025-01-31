defmodule ExShark.LazyCaptureTest do
  use ExUnit.Case, async: true
  alias ExShark.{LazyCapture, TestHelper}

  setup do
    test_pcap = TestHelper.test_pcap_path()
    {:ok, capture} = LazyCapture.start_link(test_pcap)
    {:ok, capture: capture, pcap_path: test_pcap}
  end

  describe "lazy loading" do
    test "lazy loading of packets on getitem", %{capture: capture} do
      packet = LazyCapture.get_packet(capture, 0)
      assert packet.highest_layer in ["TCP", "UDP", "ICMP", "IP"]
      assert packet.length >= 0
      assert packet.frame_info
    end

    test "lazy loading does not recreate packets", %{capture: capture} do
      packet1 = LazyCapture.get_packet(capture, 0)
      _packet2 = LazyCapture.get_packet(capture, 1)
      packet3 = LazyCapture.get_packet(capture, 0)

      # Compare packet structures
      assert packet1.highest_layer == packet3.highest_layer
      assert packet1.length == packet3.length
      assert packet1.frame_info.number == packet3.frame_info.number
    end

    test "filling cap in increments", %{capture: capture} do
      # Load first packet
      assert :ok = LazyCapture.load_packets(capture, 1)
      assert LazyCapture.get_packet(capture, 0)

      # Load two more packets
      assert :ok = LazyCapture.load_packets(capture, 2)
      assert LazyCapture.get_packet(capture, 1)
    end

    test "returns correct total packet count", %{capture: capture} do
      total = LazyCapture.total_packets(capture)
      assert is_integer(total)
      assert total > 0
    end

    test "handles out of range index", %{capture: capture} do
      result = LazyCapture.get_packet(capture, 9999)
      assert match?({:error, _}, result) or is_nil(result)
    end
  end

  describe "filtering" do
    setup %{pcap_path: pcap_path} do
      {:ok, filtered} = LazyCapture.start_link(pcap_path, filter: "ip")
      {:ok, filtered_capture: filtered}
    end

    test "applies filter correctly", %{filtered_capture: capture} do
      packet = LazyCapture.get_packet(capture, 0)
      refute is_nil(packet)

      assert packet.highest_layer in ["IP", "TCP", "UDP", "ICMP", "DNS", "HTTP"],
             "Got unexpected protocol: #{packet.highest_layer}"
    end

    test "filter affects packet count", %{
      capture: all_capture,
      filtered_capture: filtered_capture
    } do
      all_count = LazyCapture.total_packets(all_capture)
      filtered_count = LazyCapture.total_packets(filtered_capture)

      assert filtered_count > 0
      assert filtered_count <= all_count
    end
  end
end
