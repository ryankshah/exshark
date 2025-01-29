defmodule ExShark.LazyCaptureTest do
  use ExUnit.Case, async: true
  alias ExShark.LazyCapture

  setup do
    {:ok, capture} = LazyCapture.start_link(ExShark.TestHelper.test_pcap_path())
    {:ok, capture: capture}
  end

  describe "lazy loading" do
    test "lazy loading of packets on getitem", %{capture: capture} do
      packet = LazyCapture.get_packet(capture, 6)
      assert packet.highest_layer == "ICMP"
    end

    test "lazy loading does not recreate packets", %{capture: capture} do
      packet1 = LazyCapture.get_packet(capture, 6)
      _packet2 = LazyCapture.get_packet(capture, 8)
      packet3 = LazyCapture.get_packet(capture, 6)

      # Compare the entire packet structure
      assert :erlang.phash2(packet1) == :erlang.phash2(packet3)
    end

    test "filling cap in increments", %{capture: capture} do
      # Load first packet
      :ok = LazyCapture.load_packets(capture, 1)
      assert LazyCapture.get_packet(capture, 0) != nil

      # Load two more packets
      :ok = LazyCapture.load_packets(capture, 2)
      assert LazyCapture.get_packet(capture, 2) != nil
    end

    test "returns correct total packet count", %{capture: capture} do
      total = LazyCapture.total_packets(capture)
      assert total == 24
    end

    test "handles out of range index", %{capture: capture} do
      assert_raise RuntimeError, fn ->
        LazyCapture.get_packet(capture, 9999)
      end
    end
  end

  describe "filtering" do
    setup do
      {:ok, filtered_capture} =
        LazyCapture.start_link(
          ExShark.TestHelper.test_pcap_path(),
          filter: "tcp"
        )

      {:ok, filtered_capture: filtered_capture}
    end

    test "applies filter correctly", %{filtered_capture: capture} do
      packet = LazyCapture.get_packet(capture, 0)
      assert packet.highest_layer in ["TCP", "HTTP"]
    end
  end
end
