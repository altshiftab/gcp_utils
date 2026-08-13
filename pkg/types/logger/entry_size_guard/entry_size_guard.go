package entry_size_guard

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
)

const (
	// Cloud Logging rejects entries above 256 KiB outright — they vanish rather
	// than being truncated — so oversized entries must be reduced before being
	// written. The default leaves headroom for agent-added metadata.
	DefaultEntryLimit = 200 * 1024

	// When an entry exceeds the entry limit, strings above this length are
	// truncated.
	DefaultStringLimit = 4 * 1024

	// TruncatedKey marks entries that were reduced to fit the entry limit.
	TruncatedKey = "log.truncated"
)

// Writer guards an underlying writer against oversized log entries. Each Write
// call is expected to carry one entry (as slog handlers do). Entries within the
// limit pass through untouched; oversized ones are reduced by truncating long
// strings throughout the entry, and, failing that, by falling back to a minimal
// entry retaining the time, severity, message and error message.
type Writer struct {
	Writer      io.Writer
	EntryLimit  int
	StringLimit int
}

func New(writer io.Writer) *Writer {
	return &Writer{Writer: writer, EntryLimit: DefaultEntryLimit, StringLimit: DefaultStringLimit}
}

func (w *Writer) entryLimit() int {
	if w.EntryLimit <= 0 {
		return DefaultEntryLimit
	}
	return w.EntryLimit
}

func (w *Writer) stringLimit() int {
	if w.StringLimit <= 0 {
		return DefaultStringLimit
	}
	return w.StringLimit
}

// truncateString cuts the string to at most the limit, on a rune boundary, and
// appends a marker carrying the original size.
func truncateString(s string, limit int) string {
	if len(s) <= limit {
		return s
	}

	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}

	return fmt.Sprintf("%s... [truncated, %d bytes in full]", s[:cut], len(s))
}

// truncateValue walks the value tree, truncating long strings in place.
func (w *Writer) truncateValue(value any) any {
	switch typedValue := value.(type) {
	case string:
		return truncateString(typedValue, w.stringLimit())
	case map[string]any:
		for key, entryValue := range typedValue {
			typedValue[key] = w.truncateValue(entryValue)
		}
		return typedValue
	case []any:
		for i, element := range typedValue {
			typedValue[i] = w.truncateValue(element)
		}
		return typedValue
	default:
		return value
	}
}

func (w *Writer) writeUnderlying(entry []byte) error {
	underlying := w.Writer
	if underlying == nil {
		return nil_error.New("writer")
	}

	if _, err := underlying.Write(entry); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	return nil
}

func (w *Writer) Write(entry []byte) (int, error) {
	if len(entry) <= w.entryLimit() {
		if err := w.writeUnderlying(entry); err != nil {
			return 0, err
		}
		return len(entry), nil
	}

	parsedEntry := make(map[string]any)
	if err := json.Unmarshal(entry, &parsedEntry); err != nil {
		// Not an object entry; keep what fits rather than losing everything.
		cut := w.entryLimit()
		for cut > 0 && !utf8.RuneStart(entry[cut]) {
			cut--
		}
		if err := w.writeUnderlying(append(entry[:cut:cut], '\n')); err != nil {
			return 0, err
		}
		return len(entry), nil
	}
	if parsedEntry == nil {
		// A literal null unmarshals to a nil map.
		parsedEntry = make(map[string]any)
	}

	w.truncateValue(parsedEntry)
	parsedEntry[TruncatedKey] = true

	if reducedEntry, err := json.Marshal(parsedEntry); err == nil && len(reducedEntry)+1 <= w.entryLimit() {
		if err := w.writeUnderlying(append(reducedEntry, '\n')); err != nil {
			return 0, err
		}
		return len(entry), nil
	}

	// The entry is oversized even with truncated strings (e.g. through sheer
	// field count); keep the essentials. The values were already truncated above.
	minimalEntry := make(map[string]any)
	for _, key := range []string{"time", "severity", "message"} {
		if value, ok := parsedEntry[key]; ok {
			minimalEntry[key] = value
		}
	}
	if errorValue, ok := parsedEntry["error"].(map[string]any); ok {
		if errorMessage, ok := errorValue["message"]; ok {
			minimalEntry["error"] = map[string]any{"message": errorMessage}
		}
	}
	minimalEntry[TruncatedKey] = true

	minimalEntryBytes, err := json.Marshal(minimalEntry)
	if err != nil {
		return 0, fmt.Errorf("json marshal (minimal entry): %w", err)
	}

	if err := w.writeUnderlying(append(minimalEntryBytes, '\n')); err != nil {
		return 0, err
	}

	return len(entry), nil
}
