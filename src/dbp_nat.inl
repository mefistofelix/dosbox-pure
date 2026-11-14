/*
 *  RetroFire: internet access for the emulated NE2000 card.
 *
 *  A small user-mode gateway (the idea of slirp, written for this core): the guest sees a
 *  10.0.2.0/24 network with a router at 10.0.2.2 and a name server at 10.0.2.3, gets
 *  10.0.2.15 by DHCP, and its TCP connections and UDP packets are carried by ordinary
 *  sockets of the host. No raw sockets, no drivers, no special permissions.
 *
 *  Included by dbp_network.cpp. Used only while no netplay session is connected and the
 *  core option "dosbox_pure_internet" is on.
 *
 *  This program is free software; you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 */

#if defined(_WIN32) || defined(__linux__) || defined(ANDROID) || defined(__APPLE__)
#define DBP_NAT_SUPPORTED 1

#ifdef _WIN32
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
typedef SOCKET nat_sock_t;
#define NAT_BADSOCK INVALID_SOCKET
#define nat_close closesocket
static bool nat_wouldblock() { int e = WSAGetLastError(); return (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY); }
static void nat_nonblock(nat_sock_t s) { u_long on = 1; ioctlsocket(s, FIONBIO, &on); }
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
typedef int nat_sock_t;
#define NAT_BADSOCK (-1)
#define nat_close close
static bool nat_wouldblock() { return (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY || errno == EINTR); }
static void nat_nonblock(nat_sock_t s) { fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK); }
#endif

#include <string.h>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>

bool dbp_net_internet; // set from the core option

// finished name lookups: filled by the resolver threads, which may outlive the gateway
struct DBP_NAT_DnsDone { std::vector<Bit8u> query; Bit32u guest_ip; Bit16u guest_port; Bit32u addr; bool ok; };
static std::mutex dbp_nat_dns_mtx;
static std::vector<DBP_NAT_DnsDone> dbp_nat_dns_done;

struct DBP_NAT
{
	typedef DBP_NAT_DnsDone DnsDone;
	enum { MSS = 1460, WINDOW = 16384, MAX_UNACKED = 4 * MSS, TCP_BUF = 64 * 1024, MAX_TCP = 48, MAX_UDP = 32 };
	enum { TCP_FIN = 1, TCP_SYN = 2, TCP_RST = 4, TCP_PSH = 8, TCP_ACK = 16 };
	typedef void (*rx_fn)(const Bit8u* frame, Bit32u len);

	struct Tcp
	{
		nat_sock_t sock;
		Bit32u guest_ip, remote_ip;      // network order as read from the packet (big endian value)
		Bit16u guest_port, remote_port;  // host order
		bool connected, syn_acked, host_eof, fin_sent, guest_fin, host_shut, dead;
		Bit32u rcv_nxt;                  // next sequence number expected from the guest
		Bit32u iss, snd_una, snd_nxt;    // our sequence numbers; snd_una is the first byte of 'out'
		Bit32u snd_wnd;                  // window the guest offers
		std::vector<Bit8u> out;          // from the host, not yet acknowledged by the guest
		std::vector<Bit8u> to_host;      // from the guest, not yet written to the socket
		Bit64u t_start, t_progress, t_activity;
	};
	struct Udp { nat_sock_t sock; Bit32u guest_ip; Bit16u guest_port; Bit64u t_activity; };

	std::vector<Tcp> tcps;
	std::vector<Udp> udps;
	std::vector<std::vector<Bit8u> > rxq;  // frames for the guest
	Bit8u guest_mac[6];
	Bit16u ip_id;
	bool started;

	static const Bit8u* GwMac() { static const Bit8u m[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 }; return m; }
	static Bit32u IP(Bit8u a, Bit8u b, Bit8u c, Bit8u d) { return ((Bit32u)a << 24) | ((Bit32u)b << 16) | ((Bit32u)c << 8) | d; }
	static Bit32u GW() { return IP(10, 0, 2, 2); }
	static Bit32u DNS() { return IP(10, 0, 2, 3); }
	static Bit32u GUEST() { return IP(10, 0, 2, 15); }
	static Bit64u Now() { return (Bit64u)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
	static Bit16u R16(const Bit8u* p) { return (Bit16u)((p[0] << 8) | p[1]); }
	static Bit32u R32(const Bit8u* p) { return ((Bit32u)p[0] << 24) | ((Bit32u)p[1] << 16) | ((Bit32u)p[2] << 8) | p[3]; }
	static void W16(Bit8u* p, Bit16u v) { p[0] = (Bit8u)(v >> 8); p[1] = (Bit8u)v; }
	static void W32(Bit8u* p, Bit32u v) { p[0] = (Bit8u)(v >> 24); p[1] = (Bit8u)(v >> 16); p[2] = (Bit8u)(v >> 8); p[3] = (Bit8u)v; }

	static Bit32u Sum(const Bit8u* p, Bit32u len, Bit32u sum = 0)
	{
		for (; len > 1; p += 2, len -= 2) sum += (Bit32u)((p[0] << 8) | p[1]);
		if (len) sum += (Bit32u)(p[0] << 8);
		return sum;
	}
	static Bit16u Fold(Bit32u sum) { while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16); return (Bit16u)~sum; }

	DBP_NAT() : ip_id(1), started(false) { memset(guest_mac, 0xff, 6); }
	~DBP_NAT() { Reset(); }

	void Reset()
	{
		for (Tcp& t : tcps) if (t.sock != NAT_BADSOCK) nat_close(t.sock);
		for (Udp& u : udps) nat_close(u.sock);
		tcps.clear(); udps.clear(); rxq.clear();
	}

	void Start()
	{
		if (started) return;
		started = true;
		#ifdef _WIN32
		WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
		#endif
	}

	// ---- frames to the guest --------------------------------------------------------------

	// Ethernet + IPv4 header in front of 'payload_len' bytes; returns the frame, payload at +34
	std::vector<Bit8u>& NewIP(Bit8u proto, Bit32u src, Bit32u dst, Bit32u payload_len, bool broadcast = false)
	{
		rxq.push_back(std::vector<Bit8u>());
		std::vector<Bit8u>& f = rxq.back();
		f.resize(14 + 20 + payload_len);
		Bit8u* p = &f[0];
		if (broadcast) memset(p, 0xff, 6); else memcpy(p, guest_mac, 6);
		memcpy(p + 6, GwMac(), 6);
		p[12] = 0x08; p[13] = 0x00;
		Bit8u* ip = p + 14;
		ip[0] = 0x45; ip[1] = 0;
		W16(ip + 2, (Bit16u)(20 + payload_len));
		W16(ip + 4, ip_id++);
		ip[6] = 0x40; ip[7] = 0; // don't fragment
		ip[8] = 64; ip[9] = proto;
		ip[10] = ip[11] = 0;
		W32(ip + 12, src); W32(ip + 16, dst);
		W16(ip + 10, Fold(Sum(ip, 20)));
		return f;
	}

	void SendUdp(Bit32u src, Bit16u sport, Bit32u dst, Bit16u dport, const Bit8u* data, Bit32u len, bool broadcast = false)
	{
		std::vector<Bit8u>& f = NewIP(17, src, dst, 8 + len, broadcast);
		Bit8u* u = &f[34];
		W16(u, sport); W16(u + 2, dport); W16(u + 4, (Bit16u)(8 + len)); u[6] = u[7] = 0; // no checksum
		if (len) memcpy(u + 8, data, len);
	}

	void SendTcp(const Tcp& t, Bit32u seq, Bit8u flags, const Bit8u* data = NULL, Bit32u len = 0)
	{
		const bool syn = !!(flags & TCP_SYN);
		const Bit32u hlen = (syn ? 24 : 20);
		std::vector<Bit8u>& f = NewIP(6, t.remote_ip, t.guest_ip, hlen + len);
		Bit8u* h = &f[34];
		W16(h, t.remote_port); W16(h + 2, t.guest_port);
		W32(h + 4, seq); W32(h + 8, t.rcv_nxt);
		h[12] = (Bit8u)((hlen / 4) << 4); h[13] = flags;
		W16(h + 14, WINDOW); h[16] = h[17] = h[18] = h[19] = 0;
		if (syn) { h[20] = 2; h[21] = 4; W16(h + 22, MSS); }
		if (len) memcpy(h + hlen, data, len);
		Bit8u pseudo[12];
		W32(pseudo, t.remote_ip); W32(pseudo + 4, t.guest_ip); pseudo[8] = 0; pseudo[9] = 6; W16(pseudo + 10, (Bit16u)(hlen + len));
		W16(h + 16, Fold(Sum(h, hlen + len, Sum(pseudo, 12))));
	}

	// reset for a segment that belongs to no connection
	void SendRst(Bit32u guest_ip, Bit16u guest_port, Bit32u remote_ip, Bit16u remote_port, Bit32u seq, Bit32u ack)
	{
		Tcp t; t.guest_ip = guest_ip; t.guest_port = guest_port; t.remote_ip = remote_ip; t.remote_port = remote_port; t.rcv_nxt = ack;
		SendTcp(t, seq, TCP_RST | TCP_ACK);
	}

	// ---- frames from the guest ------------------------------------------------------------

	void FromGuest(const Bit8u* f, Bit32u len)
	{
		if (len < 14) return;
		Start();
		memcpy(guest_mac, f + 6, 6);
		const Bit16u type = R16(f + 12);
		if (type == 0x0806) { Arp(f, len); return; }
		if (type != 0x0800 || len < 34) return;
		const Bit8u* ip = f + 14;
		const Bit32u ihl = (ip[0] & 0xF) * 4u, total = R16(ip + 2);
		if ((ip[0] >> 4) != 4 || ihl < 20 || total < ihl || 14 + total > len) return;
		if ((R16(ip + 6) & 0x3FFF) != 0) return; // fragments are not handled
		const Bit32u src = R32(ip + 12), dst = R32(ip + 16);
		const Bit8u* pl = ip + ihl;
		const Bit32u plen = total - ihl;
		switch (ip[9])
		{
			case 1: // ICMP: answer pings to the gateway itself
				if (plen >= 8 && pl[0] == 8 && (dst == GW() || dst == DNS()))
				{
					std::vector<Bit8u>& r = NewIP(1, dst, src, plen);
					memcpy(&r[34], pl, plen);
					r[34] = 0; r[36] = r[37] = 0;
					W16(&r[36], Fold(Sum(&r[34], plen)));
				}
				break;
			case 17: if (plen >= 8) UdpFromGuest(src, dst, pl, plen); break;
			case 6: if (plen >= 20) TcpFromGuest(src, dst, pl, plen); break;
		}
	}

	void Arp(const Bit8u* f, Bit32u len)
	{
		if (len < 42 || R16(f + 20) != 1) return; // requests only
		const Bit32u sender = R32(f + 28), target = R32(f + 38);
		// the gateway answers for every address but the guest's own (its address probe must stay unanswered)
		if (target == sender || target == GUEST() || (target >> 8) != (GW() >> 8)) return;
		rxq.push_back(std::vector<Bit8u>(60));
		Bit8u* p = &rxq.back()[0];
		memcpy(p, f + 6, 6); memcpy(p + 6, GwMac(), 6);
		p[12] = 0x08; p[13] = 0x06;
		p[14] = 0; p[15] = 1; p[16] = 0x08; p[17] = 0; p[18] = 6; p[19] = 4; p[20] = 0; p[21] = 2;
		memcpy(p + 22, GwMac(), 6); W32(p + 28, target);
		memcpy(p + 32, f + 22, 6); W32(p + 38, sender);
	}

	// ---- UDP: DHCP server, name server, the rest through sockets ---------------------------

	void UdpFromGuest(Bit32u src, Bit32u dst, const Bit8u* u, Bit32u ulen)
	{
		const Bit16u sport = R16(u), dport = R16(u + 2);
		Bit32u len = R16(u + 4);
		if (len < 8 || len > ulen) return;
		const Bit8u* data = u + 8; len -= 8;
		if (dport == 67) { Dhcp(data, len); return; }
		if (dst == DNS() && dport == 53) { Dns(src, sport, data, len); return; }
		if (dst == 0xFFFFFFFF || (dst >> 28) == 0xE || (dst >> 8) == (GW() >> 8)) return; // broadcast, multicast, local
		Udp* m = NULL;
		for (Udp& x : udps) if (x.guest_port == sport && x.guest_ip == src) { m = &x; break; }
		if (!m)
		{
			if (udps.size() >= MAX_UDP) { nat_close(udps[0].sock); udps.erase(udps.begin()); }
			nat_sock_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (s == NAT_BADSOCK) return;
			nat_nonblock(s);
			Udp n; n.sock = s; n.guest_ip = src; n.guest_port = sport; n.t_activity = Now();
			udps.push_back(n);
			m = &udps.back();
		}
		sockaddr_in a; memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET; a.sin_port = htons(dport); a.sin_addr.s_addr = htonl(dst);
		sendto(m->sock, (const char*)data, (int)len, 0, (const sockaddr*)&a, sizeof(a));
		m->t_activity = Now();
	}

	void Dhcp(const Bit8u* b, Bit32u len)
	{
		if (len < 240 || b[0] != 1 || R32(b + 236) != 0x63825363) return;
		Bit8u msg = 0;
		Bit32u wanted = R32(b + 12); // the address the client says it has
		for (Bit32u i = 240; i + 1 < len && b[i] != 255; )
		{
			if (b[i] == 0) { i++; continue; }
			if (b[i] == 53 && b[i + 1] >= 1 && i + 2 < len) msg = b[i + 2];
			if (b[i] == 50 && b[i + 1] == 4 && i + 5 < len) wanted = R32(b + i + 2); // requested address
			i += 2u + b[i + 1];
		}
		if (msg != 1 && msg != 3) return; // discover -> offer, request -> ack
		// a lease from somewhere else (the core's netplay DHCP gives 192.168.x.x): refuse it, the
		// client then asks again from scratch
		const bool nak = (msg == 3 && wanted && wanted != GUEST());
		Bit8u r[300]; memset(r, 0, sizeof(r));
		r[0] = 2; r[1] = 1; r[2] = 6;
		memcpy(r + 4, b + 4, 4);         // transaction id
		memcpy(r + 10, b + 10, 2);       // flags
		if (!nak) W32(r + 16, GUEST());  // your address
		W32(r + 20, GW());               // server
		memcpy(r + 28, b + 28, 16);      // client hardware address
		W32(r + 236, 0x63825363);
		Bit8u* o = r + 240;
		*o++ = 53; *o++ = 1; *o++ = (Bit8u)(nak ? 6 : (msg == 1 ? 2 : 5));
		*o++ = 54; *o++ = 4; W32(o, GW()); o += 4;
		if (nak) { *o++ = 255; SendUdp(GW(), 67, 0xFFFFFFFF, 68, r, sizeof(r), true); return; }
		*o++ = 51; *o++ = 4; W32(o, 86400 * 30); o += 4;
		*o++ = 1; *o++ = 4; W32(o, 0xFFFFFF00); o += 4;
		*o++ = 3; *o++ = 4; W32(o, GW()); o += 4;
		*o++ = 6; *o++ = 4; W32(o, DNS()); o += 4;
		*o++ = 255;
		SendUdp(GW(), 67, 0xFFFFFFFF, 68, r, sizeof(r), true);
	}

	// name queries are answered with the host's own resolver, on a thread (it may take seconds)
	void Dns(Bit32u src, Bit16u sport, const Bit8u* q, Bit32u len)
	{
		if (len < 17 || len > 512 || (q[2] & 0x80) || R16(q + 4) != 1) return;
		std::string name;
		Bit32u i = 12;
		while (i < len && q[i])
		{
			const Bit32u n = q[i];
			if ((n & 0xC0) || i + 1 + n >= len) return;
			if (!name.empty()) name += '.';
			name.append((const char*)q + i + 1, n);
			i += 1 + n;
		}
		if (i + 5 > len) return;
		const Bit16u qtype = R16(q + i + 1);
		DnsDone d; d.query.assign(q, q + i + 5); d.guest_ip = src; d.guest_port = sport; d.addr = 0; d.ok = false;
		if (qtype != 1 || name.empty()) { std::lock_guard<std::mutex> l(dbp_nat_dns_mtx); dbp_nat_dns_done.push_back(d); return; } // only A records
		std::thread([d, name]() mutable
		{
			addrinfo hints; memset(&hints, 0, sizeof(hints));
			hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
			addrinfo* res = NULL;
			if (!getaddrinfo(name.c_str(), NULL, &hints, &res) && res)
			{
				d.addr = ntohl(((sockaddr_in*)res->ai_addr)->sin_addr.s_addr);
				d.ok = true;
			}
			if (res) freeaddrinfo(res);
			std::lock_guard<std::mutex> l(dbp_nat_dns_mtx);
			dbp_nat_dns_done.push_back(d);
		}).detach();
	}

	void DnsReplies()
	{
		std::vector<DnsDone> done;
		{ std::lock_guard<std::mutex> l(dbp_nat_dns_mtx); done.swap(dbp_nat_dns_done); }
		for (DnsDone& d : done)
		{
			std::vector<Bit8u> r(d.query);
			r[2] = (Bit8u)(0x80 | (r[2] & 0x01)); // response, recursion desired as asked
			r[3] = (Bit8u)(0x80 | (d.ok ? 0 : 3)); // recursion available; name error when not found
			W16(&r[6], (Bit16u)(d.ok ? 1 : 0)); W16(&r[8], 0); W16(&r[10], 0);
			if (d.ok)
			{
				const Bit8u a[16] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
					(Bit8u)(d.addr >> 24), (Bit8u)(d.addr >> 16), (Bit8u)(d.addr >> 8), (Bit8u)d.addr };
				r.insert(r.end(), a, a + 16);
			}
			SendUdp(DNS(), 53, d.guest_ip, d.guest_port, &r[0], (Bit32u)r.size());
		}
	}

	// ---- TCP ------------------------------------------------------------------------------

	static bool SeqLE(Bit32u a, Bit32u b) { return (Bit32s)(b - a) >= 0; }

	void TcpFromGuest(Bit32u src, Bit32u dst, const Bit8u* h, Bit32u tlen)
	{
		const Bit16u sport = R16(h), dport = R16(h + 2);
		const Bit32u seq = R32(h + 4), ack = R32(h + 8), hlen = (h[12] >> 4) * 4u;
		const Bit8u flags = h[13];
		if (hlen < 20 || hlen > tlen) return;
		const Bit8u* data = h + hlen;
		Bit32u dlen = tlen - hlen;

		Tcp* t = NULL;
		for (Tcp& x : tcps) if (!x.dead && x.guest_port == sport && x.remote_port == dport && x.remote_ip == dst && x.guest_ip == src) { t = &x; break; }

		if (flags & TCP_RST) { if (t) t->dead = true; return; }

		if (!t)
		{
			if (!(flags & TCP_SYN) || (flags & TCP_ACK))
			{
				SendRst(src, sport, dst, dport, ((flags & TCP_ACK) ? ack : 0), seq + dlen + ((flags & (TCP_SYN | TCP_FIN)) ? 1 : 0));
				return;
			}
			if ((dst >> 8) == (GW() >> 8) || tcps.size() >= MAX_TCP) { SendRst(src, sport, dst, dport, 0, seq + 1); return; }
			nat_sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (s == NAT_BADSOCK) { SendRst(src, sport, dst, dport, 0, seq + 1); return; }
			nat_nonblock(s);
			int one = 1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));
			sockaddr_in a; memset(&a, 0, sizeof(a));
			a.sin_family = AF_INET; a.sin_port = htons(dport); a.sin_addr.s_addr = htonl(dst);
			if (connect(s, (const sockaddr*)&a, sizeof(a)) != 0 && !nat_wouldblock()) { nat_close(s); SendRst(src, sport, dst, dport, 0, seq + 1); return; }
			tcps.push_back(Tcp());
			t = &tcps.back();
			t->sock = s; t->guest_ip = src; t->remote_ip = dst; t->guest_port = sport; t->remote_port = dport;
			t->connected = t->syn_acked = t->host_eof = t->fin_sent = t->guest_fin = t->host_shut = t->dead = false;
			t->rcv_nxt = seq + 1;
			t->iss = (Bit32u)(Now() * 2654435761u) ^ ((Bit32u)sport << 16) ^ dst;
			t->snd_una = t->snd_nxt = t->iss;
			t->snd_wnd = R16(h + 14);
			t->t_start = t->t_progress = t->t_activity = Now();
			return;
		}

		t->t_activity = Now();
		if (flags & TCP_SYN)
		{
			// the guest repeats its SYN: repeat our answer once the host side is connected
			if (t->connected && !t->syn_acked) SendTcp(*t, t->iss, TCP_SYN | TCP_ACK);
			return;
		}
		if (!t->connected) return;

		if (flags & TCP_ACK)
		{
			t->snd_wnd = R16(h + 14);
			if (!SeqLE(ack, t->snd_una) && SeqLE(ack, t->snd_nxt))
			{
				Bit32u n = ack - t->snd_una;
				if (!t->syn_acked) { t->syn_acked = true; n--; }
				if (n > t->out.size()) n = (Bit32u)t->out.size(); // the rest is our FIN
				t->out.erase(t->out.begin(), t->out.begin() + n);
				t->snd_una = ack;
				t->t_progress = Now();
			}
		}
		if (!t->syn_acked) return;

		bool answer = false;
		if (dlen)
		{
			if (seq == t->rcv_nxt && t->to_host.size() < TCP_BUF * 4)
			{
				t->to_host.insert(t->to_host.end(), data, data + dlen);
				t->rcv_nxt += dlen;
			}
			answer = true; // acknowledge, or tell again what is expected
		}
		if ((flags & TCP_FIN) && seq + dlen == t->rcv_nxt && !t->guest_fin)
		{
			t->guest_fin = true;
			t->rcv_nxt++;
			answer = true;
		}
		else if ((flags & TCP_FIN) && t->guest_fin) answer = true;
		if (answer) SendTcp(*t, t->snd_nxt, TCP_ACK);
	}

	void TcpPoll(Tcp& t, Bit64u now, bool readable, bool writable, bool failed)
	{
		if (!t.connected)
		{
			if (writable && !failed)
			{
				int err = 0; socklen_t el = sizeof(err);
				getsockopt(t.sock, SOL_SOCKET, SO_ERROR, (char*)&err, &el);
				if (err) failed = true;
				else
				{
					t.connected = true;
					t.snd_nxt = t.iss + 1;
					t.t_progress = now;
					SendTcp(t, t.iss, TCP_SYN | TCP_ACK);
				}
			}
			if (failed || (!t.connected && now - t.t_start > 20000))
			{
				SendRst(t.guest_ip, t.guest_port, t.remote_ip, t.remote_port, 0, t.rcv_nxt);
				t.dead = true;
			}
			return;
		}
		if (!t.syn_acked)
		{
			if (now - t.t_progress > 1000) { SendTcp(t, t.iss, TCP_SYN | TCP_ACK); t.t_progress = now; }
			if (now - t.t_start > 60000) t.dead = true;
			return;
		}

		// guest -> host
		if (!t.to_host.empty() && (writable || !t.host_shut))
		{
			int n = (int)send(t.sock, (const char*)&t.to_host[0], (int)t.to_host.size(), 0);
			if (n > 0) t.to_host.erase(t.to_host.begin(), t.to_host.begin() + n);
			else if (n < 0 && !nat_wouldblock()) failed = true;
		}
		if (t.guest_fin && t.to_host.empty() && !t.host_shut) { shutdown(t.sock, 1); t.host_shut = true; }

		// host -> guest
		if (readable && !t.host_eof && t.out.size() < TCP_BUF)
		{
			Bit8u buf[8192];
			int n = (int)recv(t.sock, (char*)buf, (int)sizeof(buf), 0);
			if (n > 0) { t.out.insert(t.out.end(), buf, buf + n); t.t_activity = now; }
			else if (n == 0) t.host_eof = true;
			else if (!nat_wouldblock()) failed = true;
		}
		if (failed)
		{
			SendTcp(t, t.snd_nxt, TCP_RST | TCP_ACK);
			t.dead = true;
			return;
		}

		// nothing acknowledged for a while: send again from the first unacknowledged byte
		if (t.snd_nxt != t.snd_una && now - t.t_progress > 600)
		{
			t.snd_nxt = t.snd_una;
			t.fin_sent = false;
			t.t_progress = now;
		}
		Bit32u limit = (t.snd_wnd < (Bit32u)MAX_UNACKED ? t.snd_wnd : (Bit32u)MAX_UNACKED);
		for (;;)
		{
			const Bit32u sent = t.snd_nxt - t.snd_una;
			if (sent >= t.out.size() || sent >= limit) break;
			Bit32u n = (Bit32u)t.out.size() - sent;
			if (n > MSS) n = MSS;
			if (n > limit - sent) n = limit - sent;
			SendTcp(t, t.snd_nxt, TCP_ACK | TCP_PSH, &t.out[sent], n);
			t.snd_nxt += n;
		}
		if (t.host_eof && !t.fin_sent && (t.snd_nxt - t.snd_una) == t.out.size())
		{
			SendTcp(t, t.snd_nxt, TCP_FIN | TCP_ACK);
			t.snd_nxt++;
			t.fin_sent = true;
		}
		// closed in both directions and everything acknowledged, or silent for a long time
		if ((t.fin_sent && t.guest_fin && t.snd_una == t.snd_nxt && t.to_host.empty()) || now - t.t_activity > 600000) t.dead = true;
	}

	void Poll(rx_fn rx)
	{
		if (started)
		{
			const Bit64u now = Now();
			if (!tcps.empty() || !udps.empty())
			{
				fd_set rd, wr, ex;
				FD_ZERO(&rd); FD_ZERO(&wr); FD_ZERO(&ex);
				int maxfd = 0;
				for (Tcp& t : tcps)
				{
					if (t.connected) FD_SET(t.sock, &rd);
					if (!t.connected || !t.to_host.empty()) FD_SET(t.sock, &wr);
					FD_SET(t.sock, &ex);
					if ((int)t.sock > maxfd) maxfd = (int)t.sock;
				}
				for (Udp& u : udps) { FD_SET(u.sock, &rd); if ((int)u.sock > maxfd) maxfd = (int)u.sock; }
				timeval tv; tv.tv_sec = 0; tv.tv_usec = 0;
				if (select(maxfd + 1, &rd, &wr, &ex, &tv) < 0) { FD_ZERO(&rd); FD_ZERO(&wr); FD_ZERO(&ex); }

				for (size_t i = 0; i != tcps.size(); i++)
					TcpPoll(tcps[i], now, !!FD_ISSET(tcps[i].sock, &rd), !!FD_ISSET(tcps[i].sock, &wr), !!FD_ISSET(tcps[i].sock, &ex));
				for (size_t i = tcps.size(); i--;)
					if (tcps[i].dead) { nat_close(tcps[i].sock); tcps.erase(tcps.begin() + i); }

				for (size_t i = udps.size(); i--;)
				{
					Udp& u = udps[i];
					if (FD_ISSET(u.sock, &rd))
					{
						Bit8u buf[1472];
						sockaddr_in a; socklen_t al = sizeof(a);
						int n = (int)recvfrom(u.sock, (char*)buf, (int)sizeof(buf), 0, (sockaddr*)&a, &al);
						if (n >= 0) { SendUdp(ntohl(a.sin_addr.s_addr), ntohs(a.sin_port), u.guest_ip, u.guest_port, buf, (Bit32u)n); u.t_activity = now; }
					}
					if (now - u.t_activity > 120000) { nat_close(u.sock); udps.erase(udps.begin() + i); }
				}
			}
			DnsReplies();
		}
		// a few frames per tick: the card's receive ring is small
		size_t n = 0;
		for (; n != rxq.size() && n != 6; n++)
		{
			if (rxq[n].size() < 60) rxq[n].resize(60); // minimum Ethernet frame
			rx(&rxq[n][0], (Bit32u)rxq[n].size());
		}
		if (n) rxq.erase(rxq.begin(), rxq.begin() + n);
		if (rxq.size() > 512) rxq.clear();
	}
};

static DBP_NAT* dbp_nat;
static void DBP_NAT_FromGuest(const Bit8u* frame, Bit32u len) { if (!dbp_nat) dbp_nat = new DBP_NAT(); dbp_nat->FromGuest(frame, len); }
static void DBP_NAT_Poll(DBP_NAT::rx_fn rx) { if (dbp_nat) dbp_nat->Poll(rx); }
static void DBP_NAT_Shutdown() { delete dbp_nat; dbp_nat = NULL; }

#else // unsupported platform
bool dbp_net_internet;
static void DBP_NAT_FromGuest(const Bit8u*, Bit32u) { }
static void DBP_NAT_Poll(void (*)(const Bit8u*, Bit32u)) { }
static void DBP_NAT_Shutdown() { }
#endif
