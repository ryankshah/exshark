defmodule ExSharkTest do
  @moduledoc """
  Tests for the main ExShark module functionality.
  """

  use ExUnit.Case, async: true
  doctest ExShark
  alias ExShark.TestHelper

  setup do
    test_pcap = TestHelper.test_pcap_path()
    {:ok, test_pcap: test_pcap}
  end

  describe "read_file/2" do
    test "reads packets from a PCAP file", %{test_pcap: test_pcap} do
      packets = ExShark.read_file(test_pcap)
      assert is_list(packets)
      assert length(packets) > 0

      # Check packet structure
      first_packet = hd(packets)
      assert first_packet.highest_layer
      assert first_packet.length
      assert first_packet.frame_info
    end

    test "applies filter when provided", %{test_pcap: test_pcap} do
      packets = ExShark.read_file(test_pcap, filter: "ip")
      assert is_list(packets)
      assert length(packets) > 0

      assert Enum.all?(packets, fn p ->
               p.highest_layer in ["IP", "TCP", "UDP", "ICMP", "DNS", "HTTP"]
             end)
    end

    test "handles invalid file path" do
      assert_raise RuntimeError, ~r/tshark error/, fn ->
        ExShark.read_file("nonexistent.pcap")
      end
    end

    test "handles invalid filter", %{test_pcap: test_pcap} do
      assert_raise RuntimeError, ~r/tshark error/, fn ->
        ExShark.read_file(test_pcap, filter: "invalid_filter")
      end
    end
  end

  describe "capture/1" do
    @tag :capture
    test "captures packets from interface" do
      packets =
        ExShark.capture(interface: "any", packet_count: 1)
        |> Enum.take(1)

      assert length(packets) == 1
      packet = hd(packets)
      assert packet.highest_layer
      assert packet.length
      assert packet.frame_info
    end
  end
end
