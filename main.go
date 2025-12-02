package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rivo/tview"
)

type PacketInfo struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	Protocol  string
	Size      int
}

type Stats struct {
	mu            sync.RWMutex
	TotalTCP      int
	TotalUDP      int
	TotalICMP     int
	TotalOther    int
	PacketsPerSec float64
	lastCount     int
	lastTime      time.Time
}

type Sniffer struct {
	iface    string
	handle   *pcap.Handle
	stats    *Stats
	packets  []PacketInfo
	mu       sync.RWMutex
	maxPkts  int
	app      *tview.Application
	table    *tview.Table
	statsBox *tview.TextView
}

func NewSniffer(iface string) *Sniffer {
	return &Sniffer{
		iface:   iface,
		stats:   &Stats{lastTime: time.Now()},
		packets: make([]PacketInfo, 0),
		maxPkts: 100,
	}
}

func (s *Sniffer) Start() error {
	var err error
	s.handle, err = pcap.OpenLive(s.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open device %s: %v", s.iface, err)
	}

	log.Printf("Started capturing on interface: %s", s.iface)

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

	go func() {
		for packet := range packetSource.Packets() {
			s.processPacket(packet)
		}
	}()

	go s.updateStats()

	return nil
}

func (s *Sniffer) processPacket(packet gopacket.Packet) {
	info := PacketInfo{
		Timestamp: time.Now(),
		Size:      len(packet.Data()),
		Protocol:  "OTHER",
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.Protocol = "TCP"
		info.SrcPort = tcp.SrcPort.String()
		info.DstPort = tcp.DstPort.String()
		s.stats.mu.Lock()
		s.stats.TotalTCP++
		s.stats.mu.Unlock()
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		info.Protocol = "UDP"
		info.SrcPort = udp.SrcPort.String()
		info.DstPort = udp.DstPort.String()
		s.stats.mu.Lock()
		s.stats.TotalUDP++
		s.stats.mu.Unlock()
	} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
		info.Protocol = "ICMP"
		s.stats.mu.Lock()
		s.stats.TotalICMP++
		s.stats.mu.Unlock()
	} else {
		s.stats.mu.Lock()
		s.stats.TotalOther++
		s.stats.mu.Unlock()
	}

	s.mu.Lock()
	s.packets = append(s.packets, info)
	if len(s.packets) > s.maxPkts {
		s.packets = s.packets[1:]
	}
	s.mu.Unlock()

	if s.app != nil {
		s.app.QueueUpdateDraw(func() {
			s.updateTable()
			s.updateStatsBox()
		})
	}
}

func (s *Sniffer) updateStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.stats.mu.Lock()
		total := s.stats.TotalTCP + s.stats.TotalUDP + s.stats.TotalICMP + s.stats.TotalOther
		elapsed := time.Since(s.stats.lastTime).Seconds()
		if elapsed > 0 {
			s.stats.PacketsPerSec = float64(total-s.stats.lastCount) / elapsed
		}
		s.stats.lastCount = total
		s.stats.lastTime = time.Now()
		s.stats.mu.Unlock()
	}
}

func (s *Sniffer) SetupUI() {
	s.app = tview.NewApplication()

	title := tview.NewTextView().
		SetText("🔍 Packet Sniffer with IDS Lite").
		SetTextAlign(tview.AlignCenter).
		SetTextColor(tview.Styles.PrimaryTextColor)

	s.table = tview.NewTable().
		SetBorders(false).
		SetFixed(1, 0)

	s.table.SetCell(0, 0, tview.NewTableCell("Timestamp").SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))
	s.table.SetCell(0, 1, tview.NewTableCell("Source → Dest").SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))
	s.table.SetCell(0, 2, tview.NewTableCell("Proto").SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))
	s.table.SetCell(0, 3, tview.NewTableCell("Size").SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))

	tableBox := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText("Live Packets").SetTextColor(tview.Styles.SecondaryTextColor), 1, 0, false).
		AddItem(s.table, 0, 1, false)

	s.statsBox = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(false)

	statsFrame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText("Statistics").SetTextColor(tview.Styles.SecondaryTextColor), 1, 0, false).
		AddItem(s.statsBox, 0, 1, false)

	alertsBox := tview.NewTextView().
		SetText("[yellow]No alerts yet[white]").
		SetDynamicColors(true).
		SetScrollable(true)

	alertsFrame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewTextView().SetText("Alerts").SetTextColor(tview.Styles.SecondaryTextColor), 1, 0, false).
		AddItem(alertsBox, 0, 1, false)

	bottomPanels := tview.NewFlex().
		AddItem(statsFrame, 0, 1, false).
		AddItem(alertsFrame, 0, 1, false)

	mainLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(title, 2, 0, false).
		AddItem(tableBox, 0, 2, false).
		AddItem(bottomPanels, 10, 0, false)

	s.app.SetRoot(mainLayout, true)
}

func (s *Sniffer) updateTable() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for row := s.table.GetRowCount() - 1; row > 0; row-- {
		s.table.RemoveRow(row)
	}

	start := 0
	if len(s.packets) > 20 {
		start = len(s.packets) - 20
	}

	for i, pkt := range s.packets[start:] {
		ts := pkt.Timestamp.Format("15:04:05")
		srcDst := fmt.Sprintf("%s:%s → %s:%s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
		if pkt.Protocol == "ICMP" {
			srcDst = fmt.Sprintf("%s → %s", pkt.SrcIP, pkt.DstIP)
		}

		s.table.SetCell(i+1, 0, tview.NewTableCell(ts))
		s.table.SetCell(i+1, 1, tview.NewTableCell(srcDst))
		s.table.SetCell(i+1, 2, tview.NewTableCell(pkt.Protocol))
		s.table.SetCell(i+1, 3, tview.NewTableCell(fmt.Sprintf("%d", pkt.Size)))
	}
}

func (s *Sniffer) updateStatsBox() {
	s.stats.mu.RLock()
	defer s.stats.mu.RUnlock()

	stats := fmt.Sprintf(
		"[green]TCP:[white] %d\n[blue]UDP:[white] %d\n[yellow]ICMP:[white] %d\n[gray]Other:[white] %d\n\n[cyan]Rate:[white] %.2f pkt/s",
		s.stats.TotalTCP,
		s.stats.TotalUDP,
		s.stats.TotalICMP,
		s.stats.TotalOther,
		s.stats.PacketsPerSec,
	)

	s.statsBox.SetText(stats)
}

func (s *Sniffer) Stop() {
	if s.handle != nil {
		s.handle.Close()
	}
	if s.app != nil {
		s.app.Stop()
	}
}

func main() {
	iface := flag.String("iface", "", "Network interface to capture (required)")
	listIfaces := flag.Bool("list", false, "List available network interfaces")
	flag.Parse()

	if *listIfaces {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Available network interfaces:")
		for _, device := range devices {
			fmt.Printf("  %s", device.Name)
			if device.Description != "" {
				fmt.Printf(" (%s)", device.Description)
			}
			fmt.Println()
		}
		return
	}

	if *iface == "" {
		fmt.Println("Error: --iface flag is required")
		fmt.Println("Use --list to see available interfaces")
		flag.Usage()
		os.Exit(1)
	}

	sniffer := NewSniffer(*iface)

	if err := sniffer.Start(); err != nil {
		log.Fatalf("Failed to start sniffer: %v", err)
	}
	defer sniffer.Stop()

	sniffer.SetupUI()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		sniffer.Stop()
		os.Exit(0)
	}()

	if err := sniffer.app.Run(); err != nil {
		log.Fatalf("Failed to run UI: %v", err)
	}
}
