defmodule ExShark.AsyncCapture do
  @moduledoc """
  Handles asynchronous packet processing with callbacks.
  """
  use Task

  @doc ~S"""
  Applies a callback function to each packet in a capture file.

  ## Options
    * `:timeout` - Maximum time in milliseconds to wait for completion (default: :infinity)
    * `:filter` - Display filter string
    * `:fields` - List of fields to extract

  ## Example
      ExShark.AsyncCapture.apply_on_packets("capture.pcap", fn p ->
        IO.puts("Processing packet #{p.frame_info.number}")
        {:ok, nil}
      end, timeout: 5000)
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
  """
  def apply_on_packets_async(file_path, callback, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, :infinity)

    task =
      Task.async(fn ->
        process_async_packets(file_path, callback, timeout, opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task) do
      {:ok, results} -> {:ok, results}
      nil -> raise "Timeout after #{timeout}ms"
      {:exit, reason} -> raise "Task failed: #{inspect(reason)}"
    end
  end

  defp process_async_packets(file_path, callback, timeout, opts) do
    file_path
    |> ExShark.read_file(opts)
    |> Task.async_stream(
      fn pkt ->
        case callback.(pkt) do
          {:ok, task} when is_struct(task, Task) ->
            {:ok, Task.await(task, timeout)}

          {:ok, result} ->
            {:ok, result}

          other ->
            other
        end
      end,
      timeout: timeout,
      ordered: true
    )
    |> Enum.to_list()
  end

  defp process_packets(file_path, callback, opts) do
    file_path
    |> ExShark.read_file(opts)
    |> Enum.each(fn pkt ->
      case callback.(pkt) do
        {:ok, _} -> :ok
        :ok -> :ok
        {:error, reason} -> raise "Callback failed: #{inspect(reason)}"
        other -> raise "Unexpected callback return: #{inspect(other)}"
      end
    end)
  rescue
    error -> reraise "Failed to process packets: #{Exception.message(error)}", __STACKTRACE__
  end

  @doc """
  Starts a live asynchronous capture with a callback function.

  ## Options
    * `:interface` - Network interface to capture on (default: "any")
    * `:filter` - Display filter string
    * `:timeout` - Maximum time to wait for each callback (default: 5000)
  """
  def capture_live(callback, opts \\ []) do
    ExShark.capture(Keyword.put_new(opts, :timeout, 5000))
    |> Stream.each(fn pkt ->
      Task.start(fn ->
        try do
          case callback.(pkt) do
            {:ok, _} -> :ok
            :ok -> :ok
            {:error, reason} -> IO.warn("Callback failed: #{inspect(reason)}")
            other -> IO.warn("Unexpected callback return: #{inspect(other)}")
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
