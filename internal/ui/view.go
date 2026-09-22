// File: internal/ui/view.go
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	borderActive   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62"))
	borderInactive = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("240"))
	
	colorAllowed   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	colorExposed   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	colorSafe      = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
	
	highlight      = lipgloss.NewStyle().Background(lipgloss.Color("236"))
	bold           = lipgloss.NewStyle().Bold(true)
)

func (m *Model) View() string {
	if m.height < 15 || m.width < 80 {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, "Terminal too small (min 80x15)")
	}

	var viewStr string
	header := ""
	if !m.isRoot {
		header = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("[!] Limited Access: Run with sudo\n")
	}

	availableHeight := m.height - 3 - lipgloss.Height(header) // Reserve footer & header
	if m.searchActive {
		availableHeight -= 2 // Search input box
	}

	listWidth := m.width
	isDualPane := m.width >= 110
	if isDualPane {
		listWidth = m.width / 2
	}

	leftPanel := m.renderLeftPanel(listWidth, availableHeight)
	
	if isDualPane {
		rightPanel := m.renderRightPanel(m.width-listWidth, availableHeight)
		viewStr = lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)
	} else {
		viewStr = leftPanel
	}

	footer := m.renderFooter()
	searchBar := ""
	if m.searchActive {
		searchBar = fmt.Sprintf("\n Search: %s█\n", m.searchQuery)
	}

	finalUI := lipgloss.JoinVertical(lipgloss.Left, header, viewStr, searchBar, footer)

	if m.showHelp {
		helpText := `=== nftop Help ===
Global:
  ?          : Toggle this help menu
  q / Ctrl+C : Quit application
  Tab        : Switch focus (List ⇄ Inspector)
  + / -      : Change scan interval (1s, 2s, 5s, 15s, 30s, 1m)
  y          : Copy service diagnostics to clipboard (OSC 52)

Navigation:
  j / k      : Move cursor down / up
  g / G      : Jump to top / bottom
  Ctrl+u/d   : Half-page scroll up / down

List Controls:
  m          : Toggle view (Detailed ⇄ Compact)
  s          : Cycle sorting (Traffic ▼, Name ▲, Port ▲)
  /          : Search (Filter by name, port, process)
  Enter      : Confirm search and return to list
  Esc        : Clear search / Close modal
  d          : Toggle Docker-only filter
  e          : Toggle Exposed-only filter (▲ EXPOSED)`

		helpLines := strings.Split(helpText, "\n")
		
		// UC-02: Implement viewport slicing for Help modal
		if m.helpOffset < 0 {
			m.helpOffset = 0
		}
		maxHelp := len(helpLines) - (m.height - 4)
		if maxHelp < 0 {
			maxHelp = 0
		}
		if m.helpOffset > maxHelp {
			m.helpOffset = maxHelp
		}

		endIdx := m.helpOffset + (m.height - 4)
		if endIdx > len(helpLines) {
			endIdx = len(helpLines)
		}

		visibleHelp := strings.Join(helpLines[m.helpOffset:endIdx], "\n")

		helpBox := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1, 2).Background(lipgloss.Color("235")).Render(visibleHelp)
		finalUI = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, helpBox)
	}

	return finalUI
}

func (m *Model) renderLeftPanel(width, height int) string {
	style := borderInactive
	if m.activePanel == PanelList {
		style = borderActive
	}
	style = style.Width(width - 2).Height(height - 2)

	sortStr := "Traffic ▼"
	if m.sortMode == SortName {
		sortStr = "Name ▲"
	} else if m.sortMode == SortPort {
		sortStr = "Port ▲"
	}

	viewStr := "Detailed"
	if m.viewMode == ModeCompact {
		viewStr = "Compact"
	}

	title := fmt.Sprintf("─ SERVICES & PORTS (%d) ─ [%s] ─ [Sort: %s] ", len(m.filtered), viewStr, sortStr)
	style = style.BorderTopForeground(lipgloss.Color("62")).BorderStyle(lipgloss.RoundedBorder())

	if len(m.filtered) == 0 {
		empty := lipgloss.Place(width-4, height-4, lipgloss.Center, lipgloss.Center, fmt.Sprintf("No matching services\nfound for \"%s\"\n\nPress [Esc] to clear", m.searchQuery))
		return style.Render(lipgloss.JoinVertical(lipgloss.Left, " " + title, empty))
	}

	itemHeight := 4
	if m.viewMode == ModeCompact {
		itemHeight = 2
	}
	maxItems := (height - 4) / itemHeight
	if maxItems < 1 {
	    maxItems = 1
	}

	if m.selectedIndex < m.listOffset {
		m.listOffset = m.selectedIndex
	} else if m.selectedIndex >= m.listOffset+maxItems {
		m.listOffset = m.selectedIndex - maxItems + 1
	}

	var content string
	for i := m.listOffset; i < len(m.filtered) && i < m.listOffset+maxItems; i++ {
		s := m.filtered[i]
		cursor := " "
		if i == m.selectedIndex {
			cursor = ">"
		}

		statusColor := colorSafe
		statusText := "● " + s.Status
		if s.Status == "ALLOWED" {
			statusColor = colorAllowed
		} else if s.Status == "EXPOSED" {
			statusColor = colorExposed
			statusText = "▲ EXPOSED"
		}

		trafficStr := "n/a"
		if !s.TrafficInfo.IsNA {
			trafficStr = fmt.Sprintf("▲ %s ▼ %s", formatBytes(s.TrafficInfo.Ingress), formatBytes(s.TrafficInfo.Egress))
		}

		var item string
		if m.viewMode == ModeDetailed {
			item = fmt.Sprintf("%s● [%s/%s] %s\n   ├─ Process:   %s (pid %s)\n   ├─ Exposure:  %s:%s\n   └─ Traffic:   %s  %s\n",
				cursor, s.Port, s.Protocol, bold.Render(s.ProcessName), s.ProcessName, s.PID, s.BindAddr, s.Port, trafficStr, statusColor.Render(statusText))
		} else {
			item = fmt.Sprintf("%s● [%s/%s] %s\n   %s  %s\n",
				cursor, s.Port, s.Protocol, bold.Render(s.ProcessName), trafficStr, statusColor.Render(statusText))
		}

		if i == m.selectedIndex && m.activePanel == PanelList {
			item = highlight.Render(item)
		}
		content += item
	}

	content = strings.TrimSuffix(content, "\n")
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, " " + title, content))
}

func (m *Model) renderRightPanel(width, height int) string {
	style := borderInactive
	if m.activePanel == PanelInspector {
		style = borderActive
	}
	style = style.Width(width - 2).Height(height - 2)

	if len(m.filtered) == 0 {
		return style.Render("─ SERVICE INSPECTOR ─\n\nNo service selected.")
	}

	s := m.filtered[m.selectedIndex]
	title := fmt.Sprintf("─ SERVICE INSPECTOR: %s ", s.ProcessName)
	rawText := generateDiagnostics(s)

	lines := strings.Split(rawText, "\n")
	
	if m.inspectorOffset < 0 {
		m.inspectorOffset = 0
	}
	maxOffset := len(lines) - (height - 4)
	if maxOffset < 0 {
		maxOffset = 0
	}
	if m.inspectorOffset > maxOffset {
		m.inspectorOffset = maxOffset
	}

	endIdx := m.inspectorOffset + (height - 4)
	if endIdx > len(lines) {
		endIdx = len(lines)
	}

	visibleText := strings.Join(lines[m.inspectorOffset:endIdx], "\n")
	return style.Render(lipgloss.JoinVertical(lipgloss.Left, " " + title, visibleText))
}

func (m *Model) renderFooter() string {
	dockStatus := "OFF"
	if m.dockerOnly {
		dockStatus = "ON"
	}
	expStatus := "OFF"
	if m.exposedOnly {
		expStatus = "ON"
	}
	
	copyToast := ""
	if m.showToast {
		copyToast = " │ [Copied to clipboard]"
	}
	
	footer := fmt.Sprintf(" Tick: %s │ Filters: [Docker: %s] [Exposed: %s]%s", intervals[m.tickIndex].String(), dockStatus, expStatus, copyToast)
	return lipgloss.NewStyle().Background(lipgloss.Color("235")).Foreground(lipgloss.Color("250")).Width(m.width).Render(footer)
}
