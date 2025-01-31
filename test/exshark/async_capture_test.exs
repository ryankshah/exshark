defmodule ExShark.AsyncCaptureTest do
  use ExUnit.Case, async: true
  alias ExShark.{AsyncCapture, TestHelper}

  setup do
    test_pcap = TestHelper.test_pcap_path()
    {:ok, test_pcap: test_pcap}
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

      # Results should be a simple list now
      assert is_list(results)
      assert length(results) > 0
      assert Enum.all?(results, &is_binary/1)
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

      {:ok, processed_layers} = AsyncCapture.apply_on_packets_async(pcap, callback)
      assert processed_layers == original_layers
    end

    test "handles callback errors", %{test_pcap: pcap} do
      callback = fn _packet ->
        {:error, "test error"}
      end

      {:ok, results} = AsyncCapture.apply_on_packets_async(pcap, callback)
      assert Enum.all?(results, fn res -> match?({:error, _}, res) end)
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
    setup do
      test_interface = TestHelper.test_interface()
      {:ok, interface: test_interface}
    end

    @tag :capture
    test "starts and stops live capture", %{interface: interface} do
      test_pid = self()
      packet_count = 1

      callback = fn packet ->
        send(test_pid, {:packet, packet.highest_layer})
        {:ok, nil}
      end

      task =
        Task.async(fn ->
          AsyncCapture.capture_live(callback,
            interface: interface,
            packet_count: packet_count
          )
        end)

      # Collect messages
      packets =
        receive do
          {:packet, layer} -> [layer]
        after
          5000 -> flunk("Timeout waiting for packets")
        end

      Task.shutdown(task)
      assert length(packets) == 1
    end

    @tag :capture
    test "handles callback errors in live capture", %{interface: interface} do
      test_pid = self()
      receive_count = 1

      callback = fn packet ->
        send(test_pid, {:packet_processed, packet.frame_info.number})
        {:error, "test error"}
      end

      task =
        Task.async(fn ->
          AsyncCapture.capture_live(callback,
            interface: interface,
            packet_count: receive_count
          )
        end)

      # Verify we got a message despite the error
      assert_receive {:packet_processed, _}, 5000
      Task.shutdown(task)
    end
  end
end
