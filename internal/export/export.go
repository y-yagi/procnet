// Package export writes accumulated per-process traffic stats to CSV or
// JSON, and provides a headless (--no-tui) periodic stdout logger.
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/y-yagi/procnet/internal/aggregate"
)

// record is the JSON/CSV shape for one process's final accumulated stats.
type record struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	SentBytes  uint64 `json:"sent_bytes"`
	RecvBytes  uint64 `json:"recv_bytes"`
	TotalBytes uint64 `json:"total_bytes"`
}

// ToFile writes stats to path. The format is chosen by the file extension:
// ".json" produces JSON, anything else (including ".csv") produces CSV.
func ToFile(path string, stats []aggregate.Stats) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("export: create %s: %w", path, err)
	}
	defer f.Close()

	if strings.EqualFold(filepath.Ext(path), ".json") {
		return WriteJSON(f, stats)
	}
	return WriteCSV(f, stats)
}

// WriteJSON writes stats as a JSON array to w.
func WriteJSON(w io.Writer, stats []aggregate.Stats) error {
	records := toRecords(stats)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(records)
}

// WriteCSV writes stats as CSV (with header) to w.
func WriteCSV(w io.Writer, stats []aggregate.Stats) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"pid", "name", "sent_bytes", "recv_bytes", "total_bytes"}); err != nil {
		return err
	}
	for _, s := range toRecords(stats) {
		row := []string{
			strconv.Itoa(s.PID),
			s.Name,
			strconv.FormatUint(s.SentBytes, 10),
			strconv.FormatUint(s.RecvBytes, 10),
			strconv.FormatUint(s.TotalBytes, 10),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func toRecords(stats []aggregate.Stats) []record {
	out := make([]record, 0, len(stats))
	for _, s := range stats {
		out = append(out, record{
			PID:        s.PID,
			Name:       s.Name,
			SentBytes:  s.SentBytes,
			RecvBytes:  s.RecvBytes,
			TotalBytes: s.TotalBytes(),
		})
	}
	return out
}

// RunHeadless periodically prints a one-line summary of aggregate totals to
// w until stop is closed. It's the --no-tui mode: no interactive TUI, just
// a running log suitable for redirecting to a file or piping.
func RunHeadless(w io.Writer, agg *aggregate.Aggregator, iface string, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			agg.Tick()
			sent, recv := agg.Totals()
			fmt.Fprintf(w, "[%s] iface=%s uptime=%s sent=%d recv=%d total=%d\n",
				time.Now().Format(time.RFC3339),
				iface,
				agg.Uptime().Round(time.Second),
				sent, recv, sent+recv,
			)
		}
	}
}
