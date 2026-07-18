// Package ui implements the procnet terminal UI using bubbletea and
// bubbles/table: a per-process traffic table refreshed roughly once a
// second, with a footer showing the monitored interface, uptime, and
// overall totals.
package ui

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/y-yagi/procnet/internal/aggregate"
)

const tickInterval = 1 * time.Second

// sortMode selects which column Model sorts the table by.
type sortMode int

const (
	sortByTotal sortMode = iota
	sortByRate
	sortModeCount
)

func (m sortMode) String() string {
	switch m {
	case sortByTotal:
		return "total"
	case sortByRate:
		return "rate"
	default:
		return "?"
	}
}

var (
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15"))
	footerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	pausedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214"))
)

// Model is the bubbletea model driving the procnet TUI. It reads directly
// from an *aggregate.Aggregator, which is safe for concurrent use, so the
// capture pipeline can keep feeding it from another goroutine while the UI
// renders.
type Model struct {
	agg   *aggregate.Aggregator
	table table.Model
	iface string

	sort   sortMode
	paused bool

	width, height int
}

// New builds a Model that renders stats from agg for the given interface
// name (shown in the footer).
func New(agg *aggregate.Aggregator, iface string) Model {
	cols := []table.Column{
		{Title: "PID", Width: 8},
		{Title: "Process", Width: 20},
		{Title: "↑ Sent", Width: 12},
		{Title: "↓ Recv", Width: 12},
		{Title: "Total", Width: 12},
		{Title: "Rate", Width: 14},
	}
	t := table.New(
		table.WithColumns(cols),
		table.WithFocused(false),
		table.WithHeight(20),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Bold(true)
	styles.Selected = styles.Selected.Bold(false)
	t.SetStyles(styles)

	return Model{
		agg:   agg,
		table: t,
		iface: iface,
	}
}

type tickMsg time.Time

func doTick() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd {
	return doTick()
}

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.table.SetWidth(msg.Width)
		if h := msg.Height - 6; h > 0 {
			m.table.SetHeight(h)
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "s":
			m.sort = (m.sort + 1) % sortModeCount
			m.refreshRows()
			return m, nil
		case "r":
			m.agg.Reset()
			m.refreshRows()
			return m, nil
		case "p":
			m.paused = !m.paused
			return m, nil
		}
		return m, nil

	case tickMsg:
		if !m.paused {
			m.agg.Tick()
			m.refreshRows()
		}
		return m, doTick()
	}
	return m, nil
}

func (m *Model) refreshRows() {
	stats := m.agg.Snapshot()
	switch m.sort {
	case sortByRate:
		sort.Slice(stats, func(i, j int) bool { return stats[i].TotalRate() > stats[j].TotalRate() })
	default:
		sort.Slice(stats, func(i, j int) bool { return stats[i].TotalBytes() > stats[j].TotalBytes() })
	}

	rows := make([]table.Row, 0, len(stats))
	for _, s := range stats {
		pidStr := fmt.Sprintf("%d", s.PID)
		if s.PID == aggregate.UnknownPID {
			pidStr = "-"
		}
		rows = append(rows, table.Row{
			pidStr,
			s.Name,
			formatBytes(s.SentBytes),
			formatBytes(s.RecvBytes),
			formatBytes(s.TotalBytes()),
			formatRate(s.TotalRate()),
		})
	}
	m.table.SetRows(rows)
}

// View implements tea.Model.
func (m Model) View() string {
	sentTotal, recvTotal := m.agg.Totals()

	statusStyled := "running"
	if m.paused {
		statusStyled = pausedStyle.Render("paused")
	}

	header := headerStyle.Render(fmt.Sprintf("procnet — interface: %s — %s", m.iface, statusStyled))
	footer := footerStyle.Render(fmt.Sprintf(
		"uptime %s | total ↑%s ↓%s (%s) | sort:%s | q quit  s sort  r reset  p pause",
		formatDuration(m.agg.Uptime()),
		formatBytes(sentTotal), formatBytes(recvTotal), formatBytes(sentTotal+recvTotal),
		m.sort,
	))

	return header + "\n" + m.table.View() + "\n" + footer
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), units[exp])
}

func formatRate(bytesPerSec float64) string {
	return formatBytes(uint64(bytesPerSec)) + "/s"
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	mi := d / time.Minute
	d -= mi * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%02d:%02d:%02d", h, mi, s)
}

// Run starts the bubbletea program and blocks until the user quits or ctx
// is cancelled (e.g. by a SIGINT/SIGTERM handler in main), whichever comes
// first. Cancelling ctx tells the TUI to shut down cleanly (restoring the
// terminal) before Run returns.
func Run(ctx context.Context, agg *aggregate.Aggregator, iface string) error {
	m := New(agg, iface)
	p := tea.NewProgram(m, tea.WithAltScreen())

	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			p.Quit()
		case <-stopWatch:
		}
	}()

	_, err := p.Run()
	return err
}
