package ui

import (
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"nftop/internal/models"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.tickCmd(), m.scanCmd())
}

func (m *Model) tickCmd() tea.Cmd {
	return tea.Tick(intervals[m.tickIndex], func(t time.Time) tea.Msg {
		return models.TickMsg(t)
	})
}

func (m *Model) scanCmd() tea.Cmd {
	return func() tea.Msg {
		return m.scanner.Scan()
	}
}

func (m *Model) copyCmd(text string) tea.Cmd {
	return func() tea.Msg {
		b64 := base64.StdEncoding.EncodeToString([]byte(text))
		os.Stdout.WriteString(fmt.Sprintf("\033]52;c;%s\007", b64))
		return models.ToastMsg{}
	}
}

func (m *Model) clearToastCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(_ time.Time) tea.Msg {
		return clearToastMsg{}
	})
}

type clearToastMsg struct{}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case models.TickMsg:
		cmds = append(cmds, m.scanCmd(), m.tickCmd())

	case models.ScanResultMsg:
		m.services = msg.Services
		m.applyFiltersAndSort()

	case models.ToastMsg:
		m.showToast = true
		cmds = append(cmds, m.clearToastCmd())

	case clearToastMsg:
		m.showToast = false

	case tea.KeyMsg:
		if m.searchActive {
			// UC-11: Isolate keystrokes during search
			switch msg.Type {
			case tea.KeyEnter:
				m.searchActive = false
			case tea.KeyEsc:
				m.searchActive = false
				m.searchQuery = ""
				m.applyFiltersAndSort()
			case tea.KeyBackspace:
				if len(m.searchQuery) > 0 {
					m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
					m.applyFiltersAndSort()
				}
			case tea.KeyUp:
				m.moveUp()
			case tea.KeyDown:
				m.moveDown()
			case tea.KeyRunes, tea.KeySpace:
				m.searchQuery += msg.String()
				m.applyFiltersAndSort()
			}
			switch msg.String() {
			case "j":
				m.moveDown()
			case "k":
				m.moveUp()
			}
			return m, tea.Batch(cmds...)
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.showHelp = !m.showHelp
		case "tab":
			if m.width >= 110 {
				if m.activePanel == PanelList {
					m.activePanel = PanelInspector
				} else {
					m.activePanel = PanelList
				}
			}
		case "+":
			if m.tickIndex < len(intervals)-1 {
				m.tickIndex++
				cmds = append(cmds, m.tickCmd())
			}
		case "-":
			if m.tickIndex > 0 {
				m.tickIndex--
				cmds = append(cmds, m.tickCmd())
			}
		case "j", "down":
			if m.showHelp {
				m.helpOffset++
			} else {
				m.moveDown()
			}
		case "k", "up":
			if m.showHelp {
				if m.helpOffset > 0 {
					m.helpOffset--
				}
			} else {
				m.moveUp()
			}
		case "g":
			if m.showHelp {
				m.helpOffset = 0
			} else if m.activePanel == PanelList {
				m.selectedIndex = 0
				m.listOffset = 0
			} else {
				m.inspectorOffset = 0
			}
		case "G":
			if m.showHelp {
				m.helpOffset = 999 // Managed in view bound check
			} else if m.activePanel == PanelList {
				m.selectedIndex = len(m.filtered) - 1
				m.listOffset = m.selectedIndex
			} else {
				m.inspectorOffset = 999
			}
		case "ctrl+u":
			if m.showHelp {
				m.helpOffset -= 10
			} else if m.activePanel == PanelList {
				m.selectedIndex -= 10
				if m.selectedIndex < 0 {
					m.selectedIndex = 0
				}
				m.listOffset -= 10
				if m.listOffset < 0 {
					m.listOffset = 0
				}
			} else {
				m.inspectorOffset -= 10
			}
		case "ctrl+d":
			if m.showHelp {
				m.helpOffset += 10
			} else if m.activePanel == PanelList {
				m.selectedIndex += 10
				if m.selectedIndex >= len(m.filtered) {
					m.selectedIndex = len(m.filtered) - 1
				}
				m.listOffset += 10
			} else {
				m.inspectorOffset += 10
			}
		case "m":
			if m.viewMode == ModeDetailed {
				m.viewMode = ModeCompact
			} else {
				m.viewMode = ModeDetailed
			}
		case "s":
			var selKey string
			if len(m.filtered) > 0 && m.selectedIndex >= 0 && m.selectedIndex < len(m.filtered) {
				selKey = m.filtered[m.selectedIndex].Port + "/" + m.filtered[m.selectedIndex].Protocol
			}
			m.sortMode = (m.sortMode + 1) % 3
			m.applyFiltersAndSort()
			if selKey != "" {
				for i, s := range m.filtered {
					if s.Port+"/"+s.Protocol == selKey {
						m.selectedIndex = i
						m.inspectorOffset = 0
						break
					}
				}
			}
		case "/":
			m.searchActive = true
		case "esc":
			if m.showHelp {
				m.showHelp = false
			}
		case "d":
			m.dockerOnly = !m.dockerOnly
			m.applyFiltersAndSort()
		case "e":
			m.exposedOnly = !m.exposedOnly
			m.applyFiltersAndSort()
		case "y":
			if len(m.filtered) > 0 {
				text := generateDiagnostics(m.filtered[m.selectedIndex])
				cmds = append(cmds, m.copyCmd(text))
			}
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) moveDown() {
	if m.activePanel == PanelList {
		if m.selectedIndex < len(m.filtered)-1 {
			m.selectedIndex++
			m.inspectorOffset = 0
		}
	} else {
		m.inspectorOffset++
	}
}

func (m *Model) moveUp() {
	if m.activePanel == PanelList {
		if m.selectedIndex > 0 {
			m.selectedIndex--
			m.inspectorOffset = 0
		}
	} else {
		if m.inspectorOffset > 0 {
			m.inspectorOffset--
		}
	}
}

func (m *Model) applyFiltersAndSort() {
	m.filtered = []models.Service{}
	q := strings.ToLower(m.searchQuery)

	for _, s := range m.services {
		if m.dockerOnly && !s.IsDocker {
			continue
		}
		if m.exposedOnly && s.Status != "EXPOSED" {
			continue
		}
		if q != "" {
			if !strings.Contains(strings.ToLower(s.ProcessName), q) &&
				!strings.Contains(s.Port, q) &&
				!strings.Contains(strings.ToLower(s.ContainerName), q) {
				continue
			}
		}
		m.filtered = append(m.filtered, s)
	}

	sort.Slice(m.filtered, func(i, j int) bool {
		switch m.sortMode {
		case SortTraffic:
			return m.filtered[i].TrafficInfo.Ingress > m.filtered[j].TrafficInfo.Ingress
		case SortName:
			return m.filtered[i].ProcessName < m.filtered[j].ProcessName
		case SortPort:
			pi, _ := strconv.Atoi(m.filtered[i].Port)
			pj, _ := strconv.Atoi(m.filtered[j].Port)
			return pi < pj
		}
		return false
	})

	if m.selectedIndex >= len(m.filtered) {
		m.selectedIndex = len(m.filtered) - 1
		if m.selectedIndex < 0 {
			m.selectedIndex = 0
		}
	}
}

func generateDiagnostics(s models.Service) string {
	var b strings.Builder
	b.WriteString("Identity & Context\n──────────────────────────────────────────────────────\n")
	b.WriteString(fmt.Sprintf("Process:     %s (PID: %s)\n", s.ProcessName, s.PID))
	b.WriteString(fmt.Sprintf("Socket:      %s:%s\n", s.BindAddr, s.Port))
	if s.IsDocker {
		b.WriteString(fmt.Sprintf("Container:   %s\n", s.ContainerName))
		b.WriteString(fmt.Sprintf("Internal IP: %s:%s\n", s.InternalIP, s.Port))
	}
	b.WriteString("\nLive Socket Telemetry\n──────────────────────────────────────────────────────\n")
	if s.TrafficInfo.IsNA {
		b.WriteString("Ingress:     N/A\nEgress:      N/A\n")
	} else {
		b.WriteString(fmt.Sprintf("Ingress:     %s/s\n", formatBytes(s.TrafficInfo.Ingress)))
		b.WriteString(fmt.Sprintf("Egress:      %s/s\n", formatBytes(s.TrafficInfo.Egress)))
	}
	b.WriteString("\nNetfilter & Firewall Rules\n──────────────────────────────────────────────────────\n")
	if s.Status == "EXPOSED" {
		b.WriteString("Status:      ▲ EXPOSED (Bypassed via Docker)\n")
	} else {
		b.WriteString(fmt.Sprintf("Status:      ● %s\n", s.Status))
	}
	if s.Rule == "" {
		b.WriteString("Rule:        -- NO MATCHING RULE FOUND --\n")
	} else {
		b.WriteString(fmt.Sprintf("Rule:        %s\n", s.Rule))
		b.WriteString(fmt.Sprintf("Chain:       %s\n", s.Chain))
		b.WriteString(fmt.Sprintf("Counters:    pkts: %s  bytes: %s\n", formatCount(s.Packets), formatBytes(s.Bytes)))
	}
	return b.String()
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatCount(c uint64) string {
	if c < 1000 {
		return fmt.Sprintf("%d", c)
	}
	return fmt.Sprintf("%.1fK", float64(c)/1000.0)
}
