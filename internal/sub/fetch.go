package sub

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Fetch loads a subscription from an HTTP(S) URL or a local file path.
func Fetch(ctx context.Context, src string, timeout time.Duration) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		hctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		req, err := http.NewRequestWithContext(hctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "netch-go/0.1")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sub: fetch: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("sub: fetch: http %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	}
	return os.ReadFile(src)
}
