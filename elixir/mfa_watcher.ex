defmodule Sniper.MfaWatcher do
  use GenServer

  def start_link(cfg), do: GenServer.start_link(__MODULE__, cfg, name: __MODULE__)

  @impl true
  def init(cfg) do
    :timer.send_interval(30000, :check_mfa)
    current = Sniper.Pool.read_mfa(cfg)
    if current != nil and current != "" do
      Sniper.Pool.rebuild_all_cache(cfg, current)
    end
    {:ok, %{cfg: cfg, mfa: current}}
  end

  @impl true
  def handle_info(:check_mfa, state) do
    handle_mfa_change(state)
  end

  @impl true
  def handle_info(_, state), do: {:noreply, state}

  defp handle_mfa_change(state) do
    new_mfa = Sniper.Pool.read_mfa(state.cfg)
    if new_mfa != nil and new_mfa != "" and new_mfa != state.mfa do
      Sniper.Pool.rebuild_all_cache(state.cfg, new_mfa)
      {:noreply, %{state | mfa: new_mfa}}
    else
      {:noreply, state}
    end
  end
end
