defmodule ExSharkTest do
  use ExUnit.Case, async: true
  doctest ExShark

  setup do
    packets = ExShark.read_file(ExShark.TestHelper.test_pcap_path())
    {:ok, packets: packets}
  end

  describe "basic operations" do
    test "count packets", %{packets: packets} do
      packet_count = Enum.count(packets)
      assert packet_count == 24
    end

    test "sum lengths", %{packets: packets} do
      total_length =
        packets
        |> Enum.map(&String.to_integer(&1.length))
        |> Enum.sum()

      assert total_length == 2178
    end

    test "layers", %{packets: packets} do
      packet_indexes = [0, 5, 6, 13, 14, 17, 23]
      test_values = Enum.map(packet_indexes, &Enum.at(packets, &1).highest_layer)
      known_values = ~w(DNS DNS ICMP ICMP TCP HTTP TCP)
      assert test_values == known_values
    end
  end

  describe "capture options" do
    test "sets capture filter" do
      packets =
        ExShark.read_file(
          ExShark.TestHelper.test_pcap_path(),
          filter: "tcp"
        )

      assert Enum.all?(packets, &(&1.highest_layer in ["TCP", "HTTP"]))
    end

    test "extracts specified fields" do
      packets =
        ExShark.read_file(
          ExShark.TestHelper.test_pcap_path(),
          fields: ["frame.time", "ip.src"]
        )

      first_packet = List.first(packets)
      assert first_packet.summary_fields["frame.time"]
    end
  end
end
