defmodule ExShark.AsyncCapture do
  @moduledoc """
  Handles asynchronous packet processing with callbacks.
  """
  use Task

  @doc """
  Applies a callback function to each packet in a capture file.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait for completion (default: :infinity)
    * `:filter` - Display filter string
    * `:fields` - List of fields to extract

  ## Example
      callback = fn packet ->
        IO.puts "Processing packet #{packet.frame_info.number}"
        {:ok, nil}
      end

      ExShark.AsyncCapture.apply_on_packets("capture.pcap", callback, timeout: 5000)

  ## Returns
    * `:ok` on successful completion
    * raises an error on timeout or other failure
  """
  def apply_on_packets(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.async(fn ->
        process_packets(file_path, callback, opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task) do
      {:ok, result} -> result
      nil -> raise "Timeout after #{timeout}ms"
      {:exit, reason} -> raise "Task failed: #{inspect(reason)}"
    end
  end

  @doc """
  Similar to apply_on_packets/3 but handles async callbacks.

  The callback function can return either {:ok, term()} or a Promise/Task.

  ## Example
      callback = async fn packet ->
        # Some async operation
        Process.sleep(100)
        {:ok, packet.frame_info.number}
      end

      ExShark.AsyncCapture.apply_on_packets_async("capture.pcap", callback)
  """
  def apply_on_packets_async(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.async(fn ->
        file_path
        |> ExShark.read_file(opts)
        |> Task.async_stream(
          fn packet ->
            case callback.(packet) do
              {:ok, result} -> result
              task when is_struct(task, Task) -> Task.await(task, timeout)
              other -> other
            end
          end,
          timeout: timeout,
          ordered: true
        )
        |> Enum.to_list()
      end)

    case Task.yield(task, timeout) || Task.shutdown(task) do
      {:ok, results} -> {:ok, results}
      nil -> raise "Timeout after #{timeout}ms"
      {:exit, reason} -> raise "Task failed: #{inspect(reason)}"
    end
  end

  # Private Functions

  defp process_packets(file_path, callback, opts) do
    file_path
    |> ExShark.read_file(opts)
    |> Enum.each(fn packet ->
      case callback.(packet) do
        {:ok, _} -> :ok
        :ok -> :ok
        {:error, reason} -> raise "Callback failed: #{inspect(reason)}"
        other -> raise "Unexpected callback return: #{inspect(other)}"
      end
    end)
  end

  @doc """
  Starts a live asynchronous capture with a callback function.

  ## Options
    * `:interface` - Network interface to capture on (default: "any")
    * `:filter` - Display filter string
    * `:duration` - Capture duration in seconds
    * `:timeout` - Maximum time to wait for each callback (default: 5000)

  ## Example
      callback = fn packet ->
        IO.puts "Live packet: #{packet.highest_layer}"
        {:ok, nil}
      end

      ExShark.AsyncCapture.capture_live(callback, interface: "eth0", filter: "tcp")
  """
  def capture_live(callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 5000)

    ExShark.capture(opts)
    |> Stream.each(fn packet ->
      Task.start(fn ->
        try do
          case callback.(packet) do
            {:ok, _} ->
              :ok

            :ok ->
              :ok

            {:error, reason} ->
              IO.warn("Callback failed: #{inspect(reason)}")

            other ->
              IO.warn("Unexpected callback return: #{inspect(other)}")
          end
        rescue
          e -> IO.warn("Callback error: #{Exception.message(e)}")
        end
      end)
    end)
    |> Stream.run()
  end

  @doc """
  Stops all ongoing async captures.
  """
  def stop_all do
    Task.Supervisor.children(ExShark.TaskSupervisor)
    |> Enum.each(&Task.Supervisor.terminate_child(ExShark.TaskSupervisor, &1))
  end
end
