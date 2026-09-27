
defmodule Sniper.Gateway do
  @gw_host ~c"gateway.discord.gg"
  @gw_port 443
  @gw_path "/?v=9&encoding=json"
  @ua      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

  def start(token, index, total, cfg) do
    spawn(fn -> connect(token, index, total, cfg) end)
  end

  defp connect(token, index, total, cfg) do
    case :gun.open(@gw_host, @gw_port, %{
      transport: :tls,
      tls_opts: [verify: :verify_none, versions: [:"tlsv1.3"]],
      protocols: [:http]
    }) do
      {:ok, conn} ->
        case :gun.await_up(conn, 5000) do
          {:ok, :http} ->
            ref = :gun.ws_upgrade(conn, @gw_path, [{"User-Agent", @ua}])
            loop(conn, ref, token, index, total, cfg, nil, true)
          _ ->
            :gun.close(conn)
            Process.sleep(1500)
            connect(token, index, total, cfg)
        end
      _ ->
        Process.sleep(1500)
        connect(token, index, total, cfg)
    end
  end

  defp loop(conn, ref, token, index, total, cfg, hb_ref, hb_acked) do
    receive do
      {:gun_upgrade, ^conn, ^ref, [<<"websocket">>], _} ->
        loop(conn, ref, token, index, total, cfg, hb_ref, hb_acked)

      {:gun_ws, ^conn, ^ref, {:text, json}} ->
        fast_check_guild_update(json, cfg)
        case json do
          <<"{\"op\":11", _::binary>> ->
            loop(conn, ref, token, index, total, cfg, hb_ref, true)
          _ ->
            {new_hb_ref, new_hb_acked} = handle(Jason.decode!(json), conn, ref, token, index, total, cfg, hb_ref, hb_acked)
            loop(conn, ref, token, index, total, cfg, new_hb_ref, new_hb_acked)
        end

      :heartbeat ->
        if !hb_acked do
          :gun.close(conn)
          reconnect(conn, hb_ref, token, index, total, cfg)
        else
          send_json(conn, ref, %{"op" => 1, "d" => nil})
          loop(conn, ref, token, index, total, cfg, hb_ref, false)
        end

      {:gun_ws, ^conn, ^ref, {:close, _, _}} ->
        reconnect(conn, hb_ref, token, index, total, cfg)

      {:gun_down, ^conn, _, _, _} ->
        reconnect(conn, hb_ref, token, index, total, cfg)

      _ ->
        loop(conn, ref, token, index, total, cfg, hb_ref, hb_acked)
    end
  end

  defp handle(%{"op" => 10, "d" => %{"heartbeat_interval" => interval}}, conn, ref, token, _idx, _tot, _cfg, old_ref, _) do
    if old_ref, do: :timer.cancel(old_ref)
    me = self()
    {:ok, tref} = :timer.send_interval(interval, me, :heartbeat)
    send_json(conn, ref, %{
      "op" => 2,
      "d"  => %{
        "token"               => token,
        "intents"             => 1,
        "properties"          => %{"os" => "Windows", "browser" => "chrome", "device" => ""},
        "guild_subscriptions" => false,
        "large_threshold"     => 0
      }
    })
    {tref, true}
  end

  defp handle(%{"op" => 11}, _, _, _, _, _, _, hb_ref, _), do: {hb_ref, true}

  defp handle(%{"op" => op}, conn, _ref, token, index, total, cfg, hb_ref, _) when op in [7, 9] do
    reconnect(conn, hb_ref, token, index, total, cfg)
    {hb_ref, true}
  end

  defp handle(%{"op" => 0, "t" => event, "d" => data}, _conn, _ref, _tok, index, total, cfg, hb_ref, hb_acked) do
    dispatch(event, data, index, total, cfg)
    {hb_ref, hb_acked}
  end

  defp handle(_, _, _, _, _, _, _, hb_ref, hb_acked), do: {hb_ref, hb_acked}

  defp dispatch("READY", %{"guilds" => guilds}, index, total, cfg) do
    mfa = Sniper.Pool.read_mfa(cfg)
    Enum.each(guilds, fn g ->
      if code = g["vanity_url_code"] do
        Sniper.Pool.set_tracked(g["id"], code)
        Sniper.Pool.build_and_cache(code, cfg, mfa)
      end
    end)
    IO.puts("[+] Monitor token #{index + 1}/#{total} baglandi (#{length(guilds)} sunucu)")
  end

  defp dispatch(_, _, _, _, _), do: :ok

  defp send_json(conn, ref, payload) do
    :gun.ws_send(conn, ref, {:text, Jason.encode!(payload)})
  end

  defp reconnect(conn, hb_ref, token, index, total, cfg) do
    if hb_ref, do: :timer.cancel(hb_ref)
    if conn,   do: :gun.close(conn)
    Process.sleep(1500)
    connect(token, index, total, cfg)
  end

  defp fast_check_guild_update(raw, cfg) do
    if String.contains?(raw, ~s("t":"GUILD_UPDATE")) do
      case String.split(raw, ~s("id":"), parts: 2) do
        [_, after_id] ->
          case String.split(after_id, ~s("), parts: 2) do
            [gid, _] ->
              case Sniper.Pool.get_tracked(gid) do
                {:ok, old_code} ->
                  case String.split(raw, ~s("premium_subscription_count":), parts: 2) do
                    [_, after_boost] ->
                      case Integer.parse(after_boost) do
                        {count, _} when count < 14 ->
                          Sniper.Pool.fire(old_code, cfg)
                        _ ->
                          case String.split(raw, ~s("vanity_url_code":"), parts: 2) do
                            [_, after_vanity] ->
                              case String.split(after_vanity, ~s("), parts: 2) do
                                [^old_code, _] -> :ok
                                _ -> Sniper.Pool.fire(old_code, cfg)
                              end
                            _ ->
                              Sniper.Pool.fire(old_code, cfg)
                          end
                      end
                    _ ->
                      case String.split(raw, ~s("vanity_url_code":"), parts: 2) do
                        [_, after_vanity] ->
                          case String.split(after_vanity, ~s("), parts: 2) do
                            [^old_code, _] -> :ok
                            _ -> Sniper.Pool.fire(old_code, cfg)
                          end
                        _ ->
                          Sniper.Pool.fire(old_code, cfg)
                      end
                  end
                _ -> :ok
              end
            _ -> :ok
          end
        _ -> :ok
      end
    end
  end
end
