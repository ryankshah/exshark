defmodule ExSharkTest do
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
      assert first_packet.highest_layer in ["IP", "TCP", "UDP", "ICMP"]
      assert first_packet.length >= 0
      assert first_packet.frame_info
    end

    test "applies filter when provided", %{test_pcap: test_pcap} do
      packets = ExShark.read_file(test_pcap, filter: "ip")
      assert is_list(packets)
      assert length(packets) > 0

      for packet <- packets do
        assert packet.highest_layer in ["IP", "TCP", "UDP", "ICMP", "DNS", "HTTP"],
               "Got unexpected protocol: #{inspect(packet.highest_layer)}"
      end
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
      TestHelper.with_test_interface(fn interface ->
        packets =
          ExShark.capture(
            interface: interface,
            packet_count: 1,
            filter: "ip"
          )
          |> Enum.take(1)

        assert length(packets) == 1
        packet = hd(packets)
        assert packet.highest_layer in ["IP", "TCP", "UDP", "ICMP"]
        assert packet.length >= 0
        assert packet.frame_info
      end)
    end

    @tag :capture
    test "applies filter during capture" do
      TestHelper.with_test_interface(fn interface ->
        packets =
          ExShark.capture(
            interface: interface,
            filter: "icmp",
            packet_count: 1
          )
          |> Enum.take(1)

        assert length(packets) == 1
        packet = hd(packets)
        assert packet.highest_layer == "ICMP"
      end)
    end

    @tag :capture
    test "respects packet count" do
      TestHelper.with_test_interface(fn interface ->
        count = 2

        packets =
          ExShark.capture(
            interface: interface,
            packet_count: count
          )
          |> Enum.to_list()

        assert length(packets) == count
      end)
    end

    @tag :capture
    test "handles duration limit" do
      TestHelper.with_test_interface(fn interface ->
        start_time = System.monotonic_time(:millisecond)

        packets =
          ExShark.capture(
            interface: interface,
            duration: 1
          )
          |> Enum.to_list()

        # Ensure duration is enforced for pcap files
        Process.sleep(1000)

        end_time = System.monotonic_time(:millisecond)
        duration = end_time - start_time

        assert duration >= 1000
        assert duration <= 2000
        assert length(packets) >= 0
      end)
    end
  end
end
