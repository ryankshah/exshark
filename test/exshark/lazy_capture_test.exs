defmodule ExShark.LazyCaptureTest do
  @moduledoc """
  Tests for the ExShark.LazyCapture module.
  """

  use ExUnit.Case, async: true
  alias ExShark.{LazyCapture, TestHelper}

  setup do
    {:ok, capture} = LazyCapture.start_link(TestHelper.test_pcap_path())
    {:ok, capture: capture}
  end

  describe "lazy loading" do
    test "lazy loading of packets on getitem", %{capture: capture} do
      packet = LazyCapture.get_packet(capture, 0)
      assert packet.highest_layer
      assert packet.length
      assert packet.frame_info
    end

    test "lazy loading does not recreate packets", %{capture: capture} do
      packet1 = LazyCapture.get_packet(capture, 6)
      _packet2 = LazyCapture.get_packet(capture, 8)
      packet3 = LazyCapture.get_packet(capture, 6)

      # Compare packet structures
      assert :erlang.phash2(packet1) == :erlang.phash2(packet3)
      assert packet1.length == packet3.length
      assert packet1.highest_layer == packet3.highest_layer
    end

    test "filling cap in increments", %{capture: capture} do
      # Load first packet
      assert :ok = LazyCapture.load_packets(capture, 1)
      assert LazyCapture.get_packet(capture, 0)

      # Load two more packets
      assert :ok = LazyCapture.load_packets(capture, 2)
      assert LazyCapture.get_packet(capture, 2)
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
    setup do
      {:ok, filtered} = LazyCapture.start_link(TestHelper.test_pcap_path(), filter: "ip")
      {:ok, filtered_capture: filtered}
    end

    test "applies filter correctly", %{filtered_capture: capture} do
      packet = LazyCapture.get_packet(capture, 0)
      assert packet
      assert packet.highest_layer in ["IP", "TCP", "UDP", "ICMP", "DNS", "HTTP"]
    end
  end
end
