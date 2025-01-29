defmodule ExShark.AsyncCaptureTest do
  use ExUnit.Case, async: true
  alias ExShark.TestHelper

  setup do
    test_pcap = TestHelper.ensure_test_pcap!()
    {:ok, test_pcap: test_pcap}
  end

  describe "synchronous callbacks" do
    test "callback called for each packet", %{test_pcap: test_pcap} do
      # Use an Agent to count packets
      {:ok, counter} = Agent.start_link(fn -> 0 end)

      callback = fn _packet ->
        Agent.update(counter, &(&1 + 1))
        {:ok, nil}
      end

      ExShark.AsyncCapture.apply_on_packets(test_pcap, callback)
      assert Agent.get(counter, & &1) > 0
    end

    test "apply on packet stops on timeout", %{test_pcap: test_pcap} do
      callback = fn _packet ->
        Process.sleep(2000)
        {:ok, nil}
      end

      assert_raise RuntimeError, ~r/Timeout after 1000ms/, fn ->
        ExShark.AsyncCapture.apply_on_packets(test_pcap, callback, timeout: 1000)
      end
    end

    test "handles callback errors", %{test_pcap: test_pcap} do
      callback = fn _packet ->
        {:error, "test error"}
      end

      assert_raise RuntimeError, ~r/Callback failed/, fn ->
        ExShark.AsyncCapture.apply_on_packets(test_pcap, callback)
      end
    end
  end

  describe "asynchronous callbacks" do
    test "handles async callbacks", %{test_pcap: test_pcap} do
      callback = fn packet ->
        task =
          Task.async(fn ->
            Process.sleep(100)
            packet.highest_layer
          end)

        {:ok, task}
      end

      {:ok, results} = ExShark.AsyncCapture.apply_on_packets_async(test_pcap, callback)
      assert length(results) > 0
    end

    test "maintains packet order with async callbacks", %{test_pcap: test_pcap} do
      original_packets = ExShark.read_file(test_pcap)

      callback = fn packet ->
        task =
          Task.async(fn ->
            # Random delay to test ordering
            Process.sleep(Enum.random(1..100))
            packet.highest_layer
          end)

        {:ok, task}
      end

      {:ok, results} = ExShark.AsyncCapture.apply_on_packets_async(test_pcap, callback)
      result_layers = Enum.map(results, fn {:ok, layer} -> layer end)
      original_layers = Enum.map(original_packets, & &1.highest_layer)

      assert result_layers == original_layers
    end

    test "handles async callback timeouts", %{test_pcap: test_pcap} do
      callback = fn _packet ->
        task =
          Task.async(fn ->
            Process.sleep(2000)
            "timeout test"
          end)

        {:ok, task}
      end

      assert_raise RuntimeError, ~r/Timeout/, fn ->
        ExShark.AsyncCapture.apply_on_packets_async(test_pcap, callback, timeout: 1000)
      end
    end
  end

  describe "live capture" do
    test "starts and stops live capture" do
      test_pid = self()
      packet_count = 1

      callback = fn packet ->
        send(test_pid, {:packet, packet.highest_layer})
        {:ok, nil}
      end

      task =
        Task.async(fn ->
          ExShark.AsyncCapture.capture_live(callback,
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

    test "handles callback errors in live capture" do
      test_pid = self()

      callback = fn packet ->
        send(test_pid, {:packet_processed, packet.frame_info.number})
        {:error, "test error"}
      end

      task =
        Task.async(fn ->
          ExShark.AsyncCapture.capture_live(callback,
            interface: "any",
            packet_count: 1
          )
        end)

      # Verify we got a message despite the error
      assert_receive {:packet_processed, _}, 5000
      Task.shutdown(task)
    end
  end

  describe "utility functions" do
    test "stops all captures" do
      # Start multiple captures
      tasks =
        for _ <- 1..3 do
          Task.async(fn ->
            ExShark.AsyncCapture.capture_live(
              fn _ -> {:ok, nil} end,
              interface: "any",
              packet_count: 1
            )
          end)
        end

      # Let them run briefly
      Process.sleep(100)

      # Stop all captures
      ExShark.AsyncCapture.stop_all()

      # Verify they're stopped
      Enum.each(tasks, fn task ->
        refute Process.alive?(task.pid)
      end)
    end
  end
end
