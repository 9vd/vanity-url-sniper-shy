defmodule Sniper.Pool do
  use GenServer

  @compile {:inline, [fire: 2, build_and_cache: 3, set_tracked: 2, get_tracked: 1]}

  @t_socks  :tls_sockets
  @t_h2     :h2_connections
  @t_req    :prebuilt_requests
  @t_guilds :tracked_guilds

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  def fire(vanity, _cfg) do
    case :ets.lookup(@t_req, vanity) do
      [{^vanity, tls_packet, path, h2_headers, body}] ->
        # HTTP/2 ve TLS soketleri ayni mikro saniyede eszamanli ateslenir
        spawn(fn ->
          Process.flag(:priority, :high)
          for {_i, pid, conn} <- :ets.tab2list(@t_h2) do
            :gun.patch(conn, path, h2_headers, body, %{reply_to: pid})
          end
        end)

        for {_i, _pid, sock} <- :ets.tab2list(@t_socks) do
          :ssl.send(sock, tls_packet)
        end
      _ -> :ok
    end
  end

  def build_and_cache(vanity, cfg, mfa_token) do
    body = ~s({"code":"#{vanity}"})
    len  = byte_size(body)
    path = "/api/v9/guilds/#{cfg["guild_id"]}/vanity-url"

    tls_packet =
      "PATCH #{path} HTTP/1.1\r\n" <>
      "Host: canary.discord.com\r\n" <>
      "Authorization: #{cfg["token"]}\r\n" <>
      (if mfa_token && mfa_token != "", do: "X-Discord-Mfa-Authorization: #{mfa_token}\r\n", else: "") <>
      "Content-Type: application/json\r\n" <>
      "Accept: */*\r\n" <>
      "Accept-Encoding: identity\r\n" <>
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n" <>
      "X-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50YnVpbGRfbnVtYmVyIjozNTU2MjR9\r\n" <>
      "Content-Length: #{len}\r\n\r\n" <>
      body

    base_h2_headers = [
      {"authorization", cfg["token"]},
      {"content-type", "application/json"},
      {"accept", "*/*"},
      {"accept-encoding", "identity"},
      {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
      {"x-super-properties", "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50YnVpbGRfbnVtYmVyIjozNTU2MjR9"}
    ]

    h2_headers =
      if mfa_token && mfa_token != "" do
        [{"x-discord-mfa-authorization", mfa_token} | base_h2_headers]
      else
        base_h2_headers
      end

    :ets.insert(@t_req, {vanity, tls_packet, path, h2_headers, body})
  end

  def rebuild_all_cache(cfg, mfa) do
    guilds = :ets.tab2list(@t_guilds)
    Enum.each(guilds, fn {_gid, code} -> build_and_cache(code, cfg, mfa) end)
    IO.puts("[MFA] Cache rebuild – #{length(guilds)} vanity")
  end

  def set_tracked(gid, code), do: :ets.insert(@t_guilds, {gid, code})

  def get_tracked(gid) do
    case :ets.lookup(@t_guilds, gid) do
      [{^gid, code}] -> {:ok, code}
      _              -> :error
    end
  end

  def read_mfa(cfg) do
    path = cfg["mfa_path"] || "./mfa.txt"
    if File.exists?(path) do
      case File.read(path) do
        {:ok, content} ->
          token = content |> String.trim() |> String.split(~r/[\r\n]+/) |> List.first()
          if token && token != "", do: String.trim(token), else: nil
        _ -> nil
      end
    else
      nil
    end
  end

  @impl true
  def init(_) do
    Process.flag(:priority, :high)
    Process.flag(:message_queue_data, :off_heap)
    :ets.new(@t_socks,  [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@t_h2,     [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@t_req,    [:set, :public, :named_table, read_concurrency: true])
    :ets.new(@t_guilds, [:set, :public, :named_table, read_concurrency: true])
    {:ok, %{}}
  end

  def spawn_workers(cfg) do
    tls_count = cfg["tls_count"] || cfg["tls_threads"] || 12
    h2_count  = cfg["h2_count"]  || cfg["http2_threads"] || 12

    for i <- 0..(tls_count - 1), do: spawn(fn ->
      Process.flag(:priority, :high)
      Process.flag(:message_queue_data, :off_heap)
      tls_worker(i, cfg)
    end)
    for i <- 0..(h2_count - 1),  do: spawn(fn ->
      Process.flag(:priority, :high)
      Process.flag(:message_queue_data, :off_heap)
      h2_worker(i, cfg)
    end)
  end

  def tls_worker(index, cfg) do
    host = ~c"canary.discord.com"
    ssl_opts = [
      versions: [:"tlsv1.3"],
      verify: :verify_none,
      server_name_indication: host,
      active: true,
      nodelay: true,
      keepalive: true,
      reuseaddr: true,
      sndbuf: 65536,
      recbuf: 65536,
      buffer: 65536,
      alpn_advertised_protocols: ["http/1.1"]
    ]
    case :ssl.connect(host, 443, ssl_opts, 5000) do
      {:ok, sock} ->
        :ets.insert(@t_socks, {index, self(), sock})
        tls_loop(index, sock, cfg)
      {:error, _} ->
        :ets.delete(@t_socks, index)
        Process.sleep(1000)
        tls_worker(index, cfg)
    end
  end

  defp tls_loop(index, sock, cfg) do
    receive do
      {:ssl, ^sock, data} ->
        str = to_string(data)
        if String.contains?(str, "HTTP/1.1 ") do
          case String.split(str, "HTTP/1.1 ", parts: 2) do
            [_, rest] -> IO.puts("HTTP #{String.slice(rest, 0..2)}")
            _ -> :ok
          end
        end
        tls_loop(index, sock, cfg)
      {:ssl_closed, ^sock} ->
        :ets.delete(@t_socks, index)
        Process.sleep(1000)
        tls_worker(index, cfg)
      {:ssl_error, ^sock, _} ->
        :ssl.close(sock)
        :ets.delete(@t_socks, index)
        Process.sleep(1000)
        tls_worker(index, cfg)
      _ ->
        tls_loop(index, sock, cfg)
    end
  end

  def h2_worker(index, cfg) do
    host = ~c"canary.discord.com"
    opts = %{
      protocols: [:http2],
      http2_opts: %{keepalive: 30000},
      tls_opts: [
        versions: [:"tlsv1.3"],
        verify: :verify_none,
        server_name_indication: host,
        nodelay: true,
        keepalive: true,
        reuseaddr: true,
        sndbuf: 65536,
        recbuf: 65536,
        buffer: 65536
      ]
    }
    case :gun.open(host, 443, opts) do
      {:ok, conn} ->
        receive do
          {:gun_up, ^conn, :http2} ->
            :ets.insert(@t_h2, {index, self(), conn})
            h2_loop(index, conn, cfg)
          {:gun_down, ^conn, _, _, _} ->
            :gun.close(conn)
            Process.sleep(1000)
            h2_worker(index, cfg)
        after
          5000 ->
            :gun.close(conn)
            Process.sleep(1000)
            h2_worker(index, cfg)
        end
      {:error, _} ->
        Process.sleep(1000)
        h2_worker(index, cfg)
    end
  end

  defp h2_loop(index, conn, cfg) do
    receive do
      {:gun_response, ^conn, _stream_ref, _is_fin, status, _headers} ->
        IO.puts("H2 #{status}")
        h2_loop(index, conn, cfg)
      {:gun_data, ^conn, _stream_ref, _is_fin, _data} ->
        h2_loop(index, conn, cfg)
      {:gun_goaway, ^conn, _last_stream_id, _err_code, _debug_data} ->
        :ets.delete(@t_h2, index)
        :gun.close(conn)
        h2_worker(index, cfg)
      {:gun_down, ^conn, _, _, _} ->
        :ets.delete(@t_h2, index)
        :gun.close(conn)
        Process.sleep(1000)
        h2_worker(index, cfg)
      {:gun_error, ^conn, _stream_ref, reason} ->
        IO.puts("H2 error: #{inspect(reason)}")
        :ets.delete(@t_h2, index)
        :gun.close(conn)
        Process.sleep(1000)
        h2_worker(index, cfg)
      _ ->
        h2_loop(index, conn, cfg)
    end
  end
end
