defmodule ExShark.AsyncCaptureTest do
  @moduledoc """
  Tests for the ExShark.AsyncCapture module.
  """

  use ExUnit.Case, async: true
  alias ExShark.{AsyncCapture, TestHelper}

  setup do
    test_pcap = TestHelper.test_pcap_path()
    {:ok, test_pcap: test_pcap}
  end

  describe "synchronous callbacks" do
    test "callback called for each packet", %{test_pcap: pcap} do
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      callback = fn _packet ->
        Agent.update(counter, &(&1 + 1))
        {:ok, nil}
      end

      AsyncCapture.apply_on_packets(pcap, callback)
      count = Agent.get(counter, & &1)
      assert count > 0
    end

    test "apply on packet stops on timeout", %{test_pcap: pcap} do
      callback = fn _packet ->
        Process.sleep(2000)
        {:ok, nil}
      end

      assert_raise RuntimeError, ~r/Timeout/, fn ->
        AsyncCapture.apply_on_packets(pcap, callback, timeout: 1000)
      end
    end

    test "handles callback errors", %{test_pcap: pcap} do
      callback = fn _packet ->
        {:error, "test error"}
      end

      assert_raise RuntimeError, ~r/Callback failed/, fn ->
        AsyncCapture.apply_on_packets(pcap, callback)
      end
    end
  end

  describe "asynchronous callbacks" do
    test "handles async callbacks", %{test_pcap: pcap} do
      callback = fn packet ->
        task =
          Task.async(fn ->
            Process.sleep(100)
            packet.highest_layer
          end)

        {:ok, task}
      end

      {:ok, results} = AsyncCapture.apply_on_packets_async(pcap, callback)

      # Fix result extraction
      processed_results = for {:ok, {:ok, layer}} <- results, do: layer

      assert length(processed_results) > 0
      assert Enum.all?(processed_results, &is_binary/1)
    end

    test "maintains packet order with async callbacks", %{test_pcap: pcap} do
      original_packets = ExShark.read_file(pcap)
      original_layers = Enum.map(original_packets, & &1.highest_layer)

      callback = fn packet ->
        task =
          Task.async(fn ->
            Process.sleep(Enum.random(1..100))
            packet.highest_layer
          end)

        {:ok, task}
      end

      {:ok, results} = AsyncCapture.apply_on_packets_async(pcap, callback)
      result_layers = for {:ok, {:ok, layer}} <- results, do: layer

      assert result_layers == original_layers
    end

    test "handles async callback timeouts", %{test_pcap: pcap} do
      callback = fn _packet ->
        task =
          Task.async(fn ->
            Process.sleep(2000)
            "timeout test"
          end)

        {:ok, task}
      end

      assert_raise RuntimeError, ~r/Timeout/, fn ->
        AsyncCapture.apply_on_packets_async(pcap, callback, timeout: 1000)
      end
    end
  end

  describe "live capture" do
    @tag :capture
    test "starts and stops live capture" do
      test_pid = self()
      packet_count = 1

      callback = fn packet ->
        send(test_pid, {:packet, packet.highest_layer})
        {:ok, nil}
      end

      task =
        Task.async(fn ->
          AsyncCapture.capture_live(callback,
            interface: "any",
            packet_count: packet_count
          )
        end)

      # Collect messages
      packets =
        for _ <- 1..packet_count do
          receive do
            {:packet, layer} -> layer
          after
            5000 -> flunk("Timeout waiting for packets")
          end
        end

      Task.shutdown(task)
      assert length(packets) == packet_count
    end

    @tag :capture
    test "handles callback errors in live capture" do
      test_pid = self()

      callback = fn packet ->
        send(test_pid, {:packet_processed, packet.frame_info.number})
        {:error, "test error"}
      end

      task =
        Task.async(fn ->
          AsyncCapture.capture_live(callback,
            interface: "any",
            packet_count: 1
          )
        end)

      # Verify we got a message despite the error
      assert_receive {:packet_processed, _}, 5000
      Task.shutdown(task)
    end
  end
end
