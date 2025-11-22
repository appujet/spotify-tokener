package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"golang.org/x/sync/singleflight"
)


type cachedTokenEntry struct {
	Token  []byte
	Expiry time.Time
}

type server struct {
	ctx        context.Context
	server     *http.Server
	tokenCache map[string]cachedTokenEntry
	cacheMutex sync.Mutex
	group      singleflight.Group
}

type spotifyTokenResponse struct {
	AccessTokenExpirationTimestampMs int64 `json:"accessTokenExpirationTimestampMs"`
}

func (s *server) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var cookies []*network.CookieParam
	for _, cookie := range r.Cookies() {
		cookies = append(cookies, &network.CookieParam{
			Name:  cookie.Name,
			Value: cookie.Value,
			URL:   spotifyURL,
		})
	}

	key := cookiesKey(cookies)

	// --- Cache check ---
	s.cacheMutex.Lock()
	entry, exists := s.tokenCache[key]
	if exists && time.Now().Before(entry.Expiry) {
		s.cacheMutex.Unlock()
		slog.InfoContext(ctx, "Returning cached Spotify token for key", slog.String("key", key))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(entry.Token)
		return
	}
	s.cacheMutex.Unlock()
	// -------------------

	// Use singleflight to prevent duplicate fetches
	v, err, _ := s.group.Do(key, func() (interface{}, error) {
		body, err := s.getAccessTokenPayload(ctx, cookies)
		if err != nil {
			return nil, err
		}

		exp, err := parseExpiry(body)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Spotify token expiry: %w", err)
		}
		slog.InfoContext(ctx, "Parsed Spotify token expiry", slog.Time("expiry", exp))

		s.cacheMutex.Lock()
		s.tokenCache[key] = cachedTokenEntry{
			Token:  body,
			Expiry: exp,
		}
		s.cacheMutex.Unlock()

		return body, nil
	})
	if err != nil {
		if !errors.Is(err, context.DeadlineExceeded) {
			slog.ErrorContext(ctx, "Failed to get access token payload", slog.Any("err", err))
		}
		http.Error(w, "Failed to get access token payload", http.StatusInternalServerError)
		return
	}

	body := v.([]byte)
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(body); err != nil {
		slog.ErrorContext(ctx, "Failed to write response", slog.Any("err", err))
	}
}

func (s *server) getAccessTokenPayload(rCtx context.Context, cookies []*network.CookieParam) ([]byte, error) {
	slog.DebugContext(rCtx, "Getting access token payload", slog.Int("cookieCount", len(cookies)))
	ctx, cancel := chromedp.NewContext(s.ctx)
	defer cancel()

	go func() {
		select {
		case <-rCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	requestIDChan := make(chan network.RequestID, 1)
	defer close(requestIDChan)

	chromedp.ListenTarget(ctx, func(ev any) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			if !strings.HasPrefix(ev.Response.URL, spotifyTokenURL) {
				return
			}
			requestIDChan <- ev.RequestID
		}
	})

	if err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(cookies) == 0 {
				return nil
			}

			if err := network.SetCookies(cookies).Do(ctx); err != nil {
				return fmt.Errorf("failed to set cookies: %w", err)
			}

			return nil
		}),
		chromedp.Navigate(spotifyURL),
	); err != nil {
		return nil, err
	}

	var requestID network.RequestID
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case requestID = <-requestIDChan:
	}

	var body []byte
	if err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		body, err = network.GetResponseBody(requestID).Do(ctx)
		return err
	})); err != nil {
		return nil, err
	}

	return body, nil
}

func (s *server) startAnonymousTokenRefresher() {
	slog.Info("Fetching initial anonymous Spotify token...")

	body, err := s.getAccessTokenPayload(s.ctx, nil)
	if err != nil {
		slog.Error("Failed to fetch initial anonymous token", slog.Any("err", err))
	} else {
		exp, err := parseExpiry(body)
		if err != nil {
			slog.Error("Failed to parse initial anonymous token expiry", slog.Any("err", err))
		} else {
			s.cacheMutex.Lock()
			s.tokenCache[""] = cachedTokenEntry{
				Token:  body,
				Expiry: exp,
			}
			s.cacheMutex.Unlock()
			slog.Info("Initial anonymous Spotify token fetched successfully", slog.Time("expiry", exp))
		}
	}
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		s.cacheMutex.Lock()
		entry, exists := s.tokenCache[""]
		s.cacheMutex.Unlock()

		if !exists {
			continue
		}

		if time.Until(entry.Expiry) > 100*time.Millisecond {
			continue
		}

		slog.Info("Refreshing anonymous Spotify token in background")
		body, err := s.getAccessTokenPayload(s.ctx, nil)
		if err != nil {
			slog.Error("Failed to refresh anonymous token, retrying in 30s", slog.Any("err", err))
			continue
		}

		exp, err := parseExpiry(body)

		if err != nil {
			slog.Error("Failed to parse refreshed anonymous token expiry", slog.Any("err", err))
			continue
		}
		s.cacheMutex.Lock()
		s.tokenCache[""] = cachedTokenEntry{
			Token:  body,
			Expiry: exp,
		}
		s.cacheMutex.Unlock()

		slog.Info("Anonymous Spotify token refreshed successfully", slog.Time("expiry", exp))
	}
}


func parseExpiry(body []byte) (time.Time, error) {
    var resp spotifyTokenResponse
    if err := json.Unmarshal(body, &resp); err != nil {
        return time.Time{}, fmt.Errorf("invalid JSON: %w", err)
    }
    if resp.AccessTokenExpirationTimestampMs <= 0 {
        return time.Time{}, fmt.Errorf("invalid expiry in token response")
    }

    t := time.UnixMilli(resp.AccessTokenExpirationTimestampMs)
    return t, nil
}


func cookiesKey(cookies []*network.CookieParam) string {
	if len(cookies) == 0 {
		return ""
	}
	var parts []string
	for _, c := range cookies {
    	parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, ";")
}