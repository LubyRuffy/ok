package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"crypto/tls"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/imgk/divert-go"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	connMap     sync.Map // tcp连接map
	defaultAddr divert.Address
)

// Config 结构体用于存储配置信息
type Config struct {
	ProxyServer  string   `yaml:"proxy_server"`
	ProxyDomains []string `yaml:"proxy_domains"`
	ProxyApps    []string `yaml:"proxy_apps"`
}

func (c *Config) ContainsDomain(responseDomain string) bool {
	for _, domain := range c.ProxyDomains {
		if strings.Contains(domain, `*.`) {
			rootDomain := strings.TrimPrefix(domain, "*.")
			if rootDomain == responseDomain || strings.HasSuffix(responseDomain, "."+rootDomain) {
				return true
			}
		} else {
			if responseDomain == domain {
				return true
			}
		}
	}
	return false
}

// DNSCache DNS缓存结构
type DNSCache struct {
	cache sync.Map
}

// Connection 表示一个TCP连接
type Connection struct {
	ID           uint16 //本地端口
	ProcessID    uint32
	ProcessName  string
	SourceAddr   string
	DestAddr     string
	ProxyEnabled bool
	CreatedAt    time.Time
}

// ConnectionManager 连接管理器
type ConnectionManager struct {
	mu          sync.RWMutex
	connections map[uint16]*Connection
}

// ProxyServer 代理服务器结构
type ProxyServer struct {
	config     *Config
	dnsCache   *DNSCache
	connMgr    *ConnectionManager
	handle     *divert.Handle
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func NewDNSCache() *DNSCache {
	return &DNSCache{}
}

func (dc *DNSCache) Set(ip string, domain string) {
	dc.cache.Store(ip, domain)
}

func (dc *DNSCache) Get(ip string) (string, bool) {
	domain, ok := dc.cache.Load(ip)
	if !ok {
		return "", false
	}
	return domain.(string), ok
}

func (dc *DNSCache) Has(ip string) bool {
	_, ok := dc.cache.Load(ip)
	return ok
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[uint16]*Connection),
	}
}

func (cm *ConnectionManager) AddConnection(conn *Connection) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connections[conn.ID] = conn
}

func (cm *ConnectionManager) RemoveConnection(id uint16) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.connections, id)
}

func NewProxyServer(configFile string) (*ProxyServer, error) {
	config := &Config{}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	filter := "!loopback && ip && ((outbound && tcp) || (inbound && (udp.SrcPort == 53 || tcp.SrcPort == 53)))"
	handle, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("opening WinDivert handle: %w", err)
	}

	return &ProxyServer{
		config:     config,
		dnsCache:   NewDNSCache(),
		connMgr:    NewConnectionManager(),
		handle:     handle,
		ctx:        ctx,
		cancelFunc: cancel,
	}, nil
}

func (ps *ProxyServer) processPkt(pkt *stack.PacketBuffer) {
	// defer pkt.DecRef()
	// dumpPktInfo(pkt.AsSlices()[0])
	if pkt.TransportProtocolNumber == header.TCPProtocolNumber {
		buf := make([]byte, pkt.Size(), pkt.Size())
		copy(buf[:], pkt.NetworkHeader().Slice())
		copy(buf[len(pkt.NetworkHeader().Slice()):], pkt.TransportHeader().Slice())
		copy(buf[len(pkt.NetworkHeader().Slice())+len(pkt.TransportHeader().Slice()):],
			pkt.Data().AsRange().ToSlice())
		// dumpPktInfo(buf)

		_, err := ps.handle.Send(buf, &defaultAddr)
		if err != nil {
			// divert.ErrInsufficientBuffer
			panic(err) // error(github.com/imgk/divert-go.Error) ErrInsufficientBuffer (122)
		}
	}
}

// readStack 循环从gvisor读数据到device
func (ps *ProxyServer) readStack(channelEp *channel.Endpoint) {
	for {
		pkt := channelEp.Read()
		if pkt != nil && pkt.Size() > 0 {
			go ps.processPkt(pkt)
		}

	}
}

var (
	lastPorts []uint16
	portLock  sync.Mutex
)

func localPorts() []uint16 {
	var ports []uint16
	connMap.Range(func(key, value any) bool {
		ports = append(ports, key.(uint16))
		return true
	})
	return ports
}

func diff(a, b []uint16) []uint16 {
	m := make(map[uint16]bool)
	for _, item := range a {
		m[item] = true
	}
	for _, item := range b {
		if _, ok := m[item]; ok {
			delete(m, item)
		} else {
			m[item] = true
		}
	}
	var diff []uint16
	for item, _ := range m {
		diff = append(diff, item)
	}
	return diff
}

func (ps *ProxyServer) Start() error {
	defer ps.handle.Close()

	go ps.socketLoop(func(sinfo *divert.Socket) {
		portLock.Lock()
		defer portLock.Unlock()

		ports := localPorts()
		if len(diff(ports, lastPorts)) > 0 {
			log.Println("+++++++++++")
			connMap.Range(func(key, value any) bool {
				log.Println(key, filepath.Base(value.(*Connection).ProcessName), value.(*Connection).SourceAddr)
				return true
			})
			log.Println("-----------")

			lastPorts = ports
		}

	})

	channelEp := ps.createStack(ps.tcpHandle)
	go ps.readStack(channelEp)

	// 创建缓冲区
	packet := make([]byte, 40960)
	addr := &divert.Address{}

	for {
		select {
		case <-ps.ctx.Done():
			return nil
		default:
			n, err := ps.handle.Recv(packet, addr)
			if err != nil {
				log.Printf("Error receiving packet: %v", err)
				continue
			}

			// 创建数据包副本以供 goroutine 使用
			packetCopy := make([]byte, n)
			copy(packetCopy, packet[:n])
			addrCopy := *addr

			go ps.handlePacket(packetCopy, &addrCopy, channelEp)
		}
	}
}

// validateTCPHeader 验证TCP头部
func validateTCPHeader(tcpHdr []byte) bool {
	if len(tcpHdr) < header.TCPMinimumSize {
		return false
	}

	dataOffset := int((tcpHdr[12] >> 4) * 4) // 转换为 int 类型
	if dataOffset < header.TCPMinimumSize || dataOffset > len(tcpHdr) {
		return false
	}

	return true
}

func dumpPktInfo(buf []byte) {
	p := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	// ipv4 := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	// tcp := p.Layer(layers.LayerTypeUDP).(*layers.TCP)
	// log.Printf("%v:%d -> %v:%d", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)
	log.Println(p.Dump())
}

func (ps *ProxyServer) handleDns(packet []byte) {
	var msg dns.Msg
	if err := msg.Unpack(packet); err == nil {
		// log.Println(msg.Answer)
		rawHost := ""

		for _, a := range msg.Answer {
			switch a.Header().Rrtype {
			case dns.TypeCNAME:
				responseDomain := strings.TrimSuffix(a.(*dns.CNAME).Hdr.Name, ".")
				if ps.config.ContainsDomain(responseDomain) {
					rawHost = responseDomain
				}
			case dns.TypeA:
				// 目前只处理ipv4
				responseDomain := strings.TrimSuffix(a.(*dns.A).Hdr.Name, ".")

				if rawHost != "" || ps.config.ContainsDomain(responseDomain) {
					if rawHost == "" {
						rawHost = responseDomain
					}
					ps.dnsCache.Set(a.(*dns.A).A.String(), rawHost)
					log.Println("hijack dns for", rawHost)
					continue
				}
			case dns.TypeAAAA:
				// 暂时不处理ipv6
			}
		}
	} else {
		os.Stderr.Write([]byte(hex.Dump(packet)))
		log.Println("msg.Unpack failed", err)
	}
}
func (ps *ProxyServer) handleUDPPacket(packet []byte, addr *divert.Address, ipv4 header.IPv4) {
	// 解析dns包
	udpHdr := header.UDP(ipv4.Payload())
	if udpHdr.SourcePort() == 53 {
		ps.handleDns(udpHdr.Payload())
	}
	// 不管如何，都回写
	ps.handle.Send(packet, addr)
}

func (ps *ProxyServer) handlePacket(packet []byte, addr *divert.Address, channelEp *channel.Endpoint) {

	if len(packet) < header.IPv4MinimumSize {
		return
	}

	ipv4 := header.IPv4(packet)
	if !ipv4.IsValid(len(packet)) {
		ps.handle.Send(packet, addr)
		return
	}

	if ipv4.TransportProtocol() == header.UDPProtocolNumber {
		ps.handleUDPPacket(packet, addr, ipv4)
		return
	}

	// 检查是否是TCP包
	if ipv4.TransportProtocol() != header.TCPProtocolNumber {
		ps.handle.Send(packet, addr)
		return
	}

	ipHeaderLength := int(ipv4.HeaderLength())
	if len(packet) < ipHeaderLength+header.TCPMinimumSize {
		ps.handle.Send(packet, addr)
		return
	}

	tcpHdr := header.TCP(ipv4.Payload())
	if !validateTCPHeader(tcpHdr) {
		ps.handle.Send(packet, addr)
		return
	}

	// 从TCP头部获取端口号
	srcPort := tcpHdr.SourcePort()
	// if tcpHdr.Flags().Contains(header.TCPFlagSyn) { // SYN flag
	// 	log.Println("->", srcPort, ipv4.DestinationAddress().String(), tcpHdr.DestinationPort())
	// }
	if srcPort == 53 && len(tcpHdr.Payload()) > 0 {
		// tcp要跳过前面的2个字节
		ps.handleDns(tcpHdr.Payload()[2:])
	}

	// 检查是否需要代理
	procName := "{{}}"
	pInfo, ok := connMap.Load(srcPort)
	for i := 0; i < 3; i++ {
		if ok && pInfo != nil {
			procName = pInfo.(*Connection).ProcessName
			break
		}
		time.Sleep(time.Millisecond * 10)
		pInfo, ok = connMap.Load(srcPort)
	}

	if pInfo == nil {
		ps.handle.Send(packet, addr)
		return
	}

	if ps.shouldProxy(ipv4.DestinationAddress().String(), procName) {
		if tcpHdr.Flags().Contains(header.TCPFlagSyn) { // SYN flag
			log.Println("->", srcPort, ipv4.DestinationAddress().String(), tcpHdr.DestinationPort())
			ps.connMgr.AddConnection(pInfo.(*Connection))
		}
		// 启动代理连接
		ps.handleProxyConnection(packet, channelEp)
	} else {
		// 不需要代理的包直接转发
		ps.handle.Send(packet, addr)
	}
}

func (ps *ProxyServer) shouldProxy(ip string, processName string) bool {
	if strings.Contains(processName, "clash") {
		return false
	}

	// 检查进程名是否在代理列表中
	for _, app := range ps.config.ProxyApps {
		if strings.Contains(strings.ToLower(processName), strings.ToLower(app)) {
			return true
		}
	}

	// 检查域名是否在代理列表中

	return ps.dnsCache.Has(ip)
}

type RawConn struct {
	handle *divert.Handle
	addr   *divert.Address
}

func (pc *RawConn) Read(p []byte) (int, error) {
	n, err := pc.handle.Recv(p, pc.addr)
	return int(n), err
}

func (pc *RawConn) Write(p []byte) (int, error) {
	n, err := pc.handle.Send(p, pc.addr)
	return int(n), err
}

func (ps *ProxyServer) handleProxyConnection(packet []byte, channelEp *channel.Endpoint) {
	// dumpPktInfo(packet)
	pktBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	channelEp.InjectInbound(header.IPv4ProtocolNumber, pktBuffer)
	pktBuffer.DecRef()
}

func (ps *ProxyServer) createStack(f func(r *tcp.ForwarderRequest)) *channel.Endpoint {
	const NICID = tcpip.NICID(1)
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	channelEp := channel.New(512, uint32(1500), "")
	channelEp.LinkEPCapabilities |= stack.CapabilityRXChecksumOffload // 去掉checksum的校验和机制
	ep := stack.LinkEndpoint(channelEp)
	// ep = sniffer.New(ep)

	tcperr := s.CreateNIC(NICID, ep)
	if tcperr != nil {
		log.Panic(tcperr)
	}

	// set Promiscuous
	if tcperr := s.SetPromiscuousMode(NICID, true); tcperr != nil {
		panic(fmt.Errorf("set promiscuous mode: %s", tcperr))
	}
	// set spoofing模式
	if tcperr := s.SetSpoofing(NICID, true); tcperr != nil {
		panic(fmt.Errorf("set spoofing: %s", tcperr))
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         NICID,
		},
	})

	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 16<<10, 1<<15, f).HandlePacket)

	return channelEp
}

func (ps *ProxyServer) connectToProxy() (net.Conn, error) {
	u, _ := url.Parse(ps.config.ProxyServer)
	switch u.Scheme {
	case "https":
		port := "443"
		if u.Port() != "" {
			port = u.Port()
		}
		httpsProxyHostInfo := fmt.Sprintf("%v:%v", u.Hostname(), port)
		return tls.Dial("tcp", httpsProxyHostInfo, &tls.Config{
			//ServerName: httpsProxyHost, // 如果直接是域名请求，就不用配置
			//InsecureSkipVerify: true, // 如果是签名的证书并且是域名请求，就不用配置
		})

	case "http":
		port := "80"
		if u.Port() != "" {
			port = u.Port()
		}
		httpsProxyHostInfo := fmt.Sprintf("%v:%v", u.Hostname(), port)
		return net.Dial("tcp", httpsProxyHostInfo)
	}
	return nil, errors.New("unsupported proxy scheme")
}

func (ps *ProxyServer) httpsDial(network, addr string) (conn net.Conn, err error) {
	conn, err = ps.connectToProxy()
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodConnect, "", nil)
	if err != nil {
		return
	}
	req.Host = addr
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	err = req.Write(conn)
	if err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	r, err := http.ReadResponse(reader, req)
	if err != nil {
		return
	}
	if r.StatusCode != http.StatusOK {
		err = fmt.Errorf("http response code error: %v", r.StatusCode)
		return
	}

	return
}

// tcpHandle 劫持tcp
func (ps *ProxyServer) tcpHandle(r *tcp.ForwarderRequest) {

	id := r.ID()
	wq := waiter.Queue{}
	ep, tcperr := r.CreateEndpoint(&wq)
	if tcperr != nil {
		r.Complete(true)
		return
	}
	defer ep.Close()

	r.Complete(false)

	host := id.LocalAddress.String()
	if v, ok := ps.dnsCache.Get(id.LocalAddress.String()); ok {
		host = v
	}
	c, err := ps.httpsDial("tcp", fmt.Sprintf("%s:%d", host, id.LocalPort))
	if err != nil {
		log.Println("httpsDial failed", err)
		// r.Complete(true)
		return
	}
	defer c.Close()

	cep := gonet.NewTCPConn(&wq, ep)
	defer cep.Close()

	go func() {
		_, err := io.Copy(cep, c)
		if err != nil {
			log.Println(err)
		}
	}()
	_, err = io.Copy(c, cep)
	if err != nil {
		log.Println(err)
	}
	log.Println("finished")
	// r.Complete(true)

	ps.connMgr.RemoveConnection(id.RemotePort)
}

func parseIPv4Address(addr [16]uint8) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[3], addr[2], addr[1], addr[0])
}

// divertConnectionInfo 信息
func divertConnectionInfo(sinfo *divert.Socket) *Connection {
	pName, err := processPidToName(sinfo.ProcessID)
	if err != nil {
		pName = "unknown"
	}
	return &Connection{
		ID:           sinfo.LocalPort,
		SourceAddr:   parseIPv4Address(sinfo.RemoteAddress),
		DestAddr:     parseIPv4Address(sinfo.LocalAddress),
		ProcessID:    sinfo.ProcessID,
		ProcessName:  pName,
		CreatedAt:    time.Now(),
		ProxyEnabled: false,
	}
}
func (ps *ProxyServer) socketLoop(onSocket func(*divert.Socket)) {
	hd, err := divert.Open("outbound && !loopback and tcp", divert.LayerSocket, divert.PriorityHighest, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("open handle error: %v", err)
		return
	}
	defer hd.Close()

	buf := make([]byte, 1)
	addr := divert.Address{}
	for {
		_, err := hd.Recv(buf, &addr)
		if err != nil {
			log.Printf("recv error: %v", err)
			continue
		}

		if addr.Event() != divert.EventSocketConnect && addr.Event() != divert.EventSocketClose {
			continue
		}

		sinfo := addr.Socket()
		key := sinfo.LocalPort

		switch addr.Event() {
		case divert.EventSocketConnect:
			if _, ok := connMap.Load(key); !ok {
				c := divertConnectionInfo(sinfo)
				if ps.shouldProxy(parseIPv4Address(sinfo.RemoteAddress), c.ProcessName) {
					connMap.Store(key, c)
				}
			}
		case divert.EventSocketClose:
			if _, ok := connMap.LoadAndDelete(key); ok {
				log.Println("[SOCKET] close localPort:", key)
			}

		}
		go onSocket(sinfo)
	}
}

// GetInterfaceIndex is ...
func GetInterfaceIndex() (uint32, uint32, error) {
	const filter = "not loopback and outbound and (ip.DstAddr = 8.8.8.8 or ipv6.DstAddr = 2001:4860:4860::8888) and tcp.DstPort = 53"
	hd, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagSniff)
	if err != nil {
		return 0, 0, fmt.Errorf("open interface handle error: %w", err)
	}
	//defer hd.Close()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		conn, err := net.DialTimeout("tcp4", "8.8.8.8:53", time.Second)
		if err != nil {
			return
		}

		conn.Close()
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()

		conn, err := net.DialTimeout("tcp6", "[2001:4860:4860::8888]:53", time.Second)
		if err != nil {
			return
		}

		conn.Close()
	}(wg)

	addr := divert.Address{}
	buff := make([]byte, 1500)

	if _, err := hd.Recv(buff, &addr); err != nil {
		return 0, 0, err
	}

	if err := hd.Shutdown(divert.ShutdownBoth); err != nil {
		return 0, 0, fmt.Errorf("shutdown interface handle error: %w", err)
	}

	if err := hd.Close(); err != nil {
		return 0, 0, fmt.Errorf("close interface handle error: %w", err)
	}

	wg.Wait()

	nw := addr.Network()
	return nw.InterfaceIndex, nw.SubInterfaceIndex, nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	ifIdx, subIfIdx, err := GetInterfaceIndex()
	if err != nil {
		log.Fatal(err)
	}

	defaultAddr.Network().InterfaceIndex = ifIdx
	defaultAddr.Network().SubInterfaceIndex = subIfIdx

	if err := exec.Command("ipconfig", "/flushdns").Run(); err != nil {
		log.Fatal(err)
	}

	server, err := NewProxyServer("config.yaml")
	if err != nil {
		log.Fatalf("Error creating proxy server: %v", err)
	}

	log.Println("Starting proxy server...")
	if err := server.Start(); err != nil {
		log.Fatalf("Error starting proxy server: %v", err)
	}
}
