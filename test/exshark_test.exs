defmodule ExSharkTest do
  use ExUnit.Case, async: true
  doctest ExShark

  alias ExShark.TestHelper

  setup do
    test_pcap = TestHelper.ensure_test_pcap!()
    {:ok, test_pcap: test_pcap}
  end

  describe "read_file/2" do
    test "reads packets from a PCAP file", %{test_pcap: test_pcap} do
      packets = ExShark.read_file(test_pcap)
      assert is_list(packets)
    end

    test "applies filter when provided", %{test_pcap: test_pcap} do
      packets = ExShark.read_file(test_pcap, filter: "ip")
      assert is_list(packets)
    end
  end

  describe "capture/1" do
    @tag :capture
    test "captures packets from interface" do
      packets =
        ExShark.capture(interface: "any", packet_count: 1)
        |> Enum.take(1)

      assert length(packets) == 1
    end
  end
end