defmodule Sniper.Monitor do
  use GenServer

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @impl true
  def init(_) do
    send(self(), :boot)
    {:ok, %{}}
  end

  @impl true
  def handle_info(:boot, state) do
    cfg    = Sniper.Config.load()
    tokens = Sniper.Config.monitor_tokens(cfg)
    total  = length(tokens)

    IO.puts("config loaded → token: #{String.slice(cfg["token"], 0..9)}… | guild: #{cfg["guild_id"]}")
    tls_n = cfg["tls_count"] || cfg["tls_threads"] || 12
    h2_n  = cfg["h2_count"]  || cfg["http2_threads"] || 12
    IO.puts("  threads:      #{tls_n} TLS + #{h2_n} HTTP/2")

    Sniper.Pool.spawn_workers(cfg)

    {:ok, _} = Sniper.MfaWatcher.start_link(cfg)

    Enum.with_index(tokens)
    |> Enum.each(fn {tok, idx} -> Sniper.Gateway.start(tok, idx, total, cfg) end)

    IO.puts("\nsniper online - waiting for vanity drops\n")
    {:noreply, state}
  end
end
