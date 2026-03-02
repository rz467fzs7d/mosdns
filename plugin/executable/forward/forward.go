/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package fastforward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/IrineSistiana/mosdns/v5/coremain"
	"github.com/IrineSistiana/mosdns/v5/pkg/pool"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/pkg/upstream"
	"github.com/IrineSistiana/mosdns/v5/pkg/utils"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const PluginType = "forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() any { return new(Args) })
	sequence.MustRegExecQuickSetup(PluginType, quickSetup)
}

const (
	maxConcurrentQueries = 3
	queryTimeout         = time.Second * 5
)

// Voting config for multi-upstream consensus
type Voting struct {
	Threshold int `yaml:"threshold"` // Minimum responses needed for consensus
	Timeout   int `yaml:"timeout"`   // Wait timeout in milliseconds
}

type Args struct {
	Upstreams  []UpstreamConfig `yaml:"upstreams"`
	Concurrent int              `yaml:"concurrent"`

	// Voting consensus configuration
	Voting *Voting `yaml:"voting"`

	// Global options.
	Socks5       string `yaml:"socks5"`
	SoMark       int    `yaml:"so_mark"`
	BindToDevice string `yaml:"bind_to_device"`
	Bootstrap    string `yaml:"bootstrap"`
	BootstrapVer int    `yaml:"bootstrap_version"`
}

type UpstreamConfig struct {
	Tag         string `yaml:"tag"`
	Addr        string `yaml:"addr"` // Required.
	DialAddr    string `yaml:"dial_addr"`
	IdleTimeout int    `yaml:"idle_timeout"`

	// Deprecated: This option has no affect.
	// TODO: (v6) Remove this option.
	MaxConns           int  `yaml:"max_conns"`
	EnablePipeline     bool `yaml:"enable_pipeline"`
	EnableHTTP3        bool `yaml:"enable_http3"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`

	Socks5       string `yaml:"socks5"`
	SoMark       int    `yaml:"so_mark"`
	BindToDevice string `yaml:"bind_to_device"`
	Bootstrap    string `yaml:"bootstrap"`
	BootstrapVer int    `yaml:"bootstrap_version"`
}

func Init(bp *coremain.BP, args any) (any, error) {
	f, err := NewForward(args.(*Args), Opts{Logger: bp.L(), MetricsTag: bp.Tag()})
	if err != nil {
		return nil, err
	}
	if err := f.RegisterMetricsTo(prometheus.WrapRegistererWithPrefix(PluginType+"_", bp.M().GetMetricsReg())); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

var _ sequence.Executable = (*Forward)(nil)
var _ sequence.QuickConfigurableExec = (*Forward)(nil)

type Forward struct {
	args *Args

	logger       *zap.Logger
	us           []*upstreamWrapper
	tag2Upstream map[string]*upstreamWrapper // for fast tag lookup only.
}

type Opts struct {
	Logger     *zap.Logger
	MetricsTag string
}

// NewForward inits a Forward from given args.
// args must contain at least one upstream.
func NewForward(args *Args, opt Opts) (*Forward, error) {
	if len(args.Upstreams) == 0 {
		return nil, errors.New("no upstream is configured")
	}
	if opt.Logger == nil {
		opt.Logger = zap.NewNop()
	}

	f := &Forward{
		args:         args,
		logger:       opt.Logger,
		tag2Upstream: make(map[string]*upstreamWrapper),
	}

	applyGlobal := func(c *UpstreamConfig) {
		utils.SetDefaultString(&c.Socks5, args.Socks5)
		utils.SetDefaultUnsignNum(&c.SoMark, args.SoMark)
		utils.SetDefaultString(&c.BindToDevice, args.BindToDevice)
		utils.SetDefaultString(&c.Bootstrap, args.Bootstrap)
		utils.SetDefaultUnsignNum(&c.BootstrapVer, args.BootstrapVer)
	}

	for i, c := range args.Upstreams {
		if len(c.Addr) == 0 {
			return nil, fmt.Errorf("#%d upstream invalid args, addr is required", i)
		}
		applyGlobal(&c)

		uw := newWrapper(i, c, opt.MetricsTag)
		uOpt := upstream.Opt{
			DialAddr:       c.DialAddr,
			Socks5:         c.Socks5,
			SoMark:         c.SoMark,
			BindToDevice:   c.BindToDevice,
			IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
			EnablePipeline: c.EnablePipeline,
			EnableHTTP3:    c.EnableHTTP3,
			Bootstrap:      c.Bootstrap,
			BootstrapVer:   c.BootstrapVer,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: c.InsecureSkipVerify,
				ClientSessionCache: tls.NewLRUClientSessionCache(4),
			},
			Logger:        opt.Logger,
			EventObserver: uw,
		}

		u, err := upstream.NewUpstream(c.Addr, uOpt)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to init upstream #%d: %w", i, err)
		}
		uw.u = u
		f.us = append(f.us, uw)

		if len(c.Tag) > 0 {
			if _, dup := f.tag2Upstream[c.Tag]; dup {
				_ = f.Close()
				return nil, fmt.Errorf("duplicated upstream tag %s", c.Tag)
			}
			f.tag2Upstream[c.Tag] = uw
		}
	}

	return f, nil
}

func (f *Forward) RegisterMetricsTo(r prometheus.Registerer) error {
	for _, wu := range f.us {
		// Only register metrics for upstream that has a tag.
		if len(wu.cfg.Tag) == 0 {
			continue
		}
		if err := wu.registerMetricsTo(r); err != nil {
			return err
		}
	}
	return nil
}

func (f *Forward) Exec(ctx context.Context, qCtx *query_context.Context) (err error) {
	r, err := f.exchange(ctx, qCtx, f.us)
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return nil
}

// QuickConfigureExec format: [upstream_tag]...
func (f *Forward) QuickConfigureExec(args string) (any, error) {
	var us []*upstreamWrapper
	if len(args) == 0 { // No args, use all upstreams.
		us = f.us
	} else { // Pick up upstreams by tags.
		for _, tag := range strings.Fields(args) {
			u := f.tag2Upstream[tag]
			if u == nil {
				return nil, fmt.Errorf("cannot find upstream by tag %s", tag)
			}
			us = append(us, u)
		}
	}
	var execFunc sequence.ExecutableFunc = func(ctx context.Context, qCtx *query_context.Context) error {
		r, err := f.exchange(ctx, qCtx, us)
		if err != nil {
			return err
		}
		qCtx.SetResponse(r)
		return nil
	}
	return execFunc, nil
}

func (f *Forward) Close() error {
	for _, u := range f.us {
		_ = u.Close()
	}
	return nil
}

func (f *Forward) exchange(ctx context.Context, qCtx *query_context.Context, us []*upstreamWrapper) (*dns.Msg, error) {
	if len(us) == 0 {
		return nil, errors.New("no upstream to exchange")
	}

	queryPayload, err := pool.PackBuffer(qCtx.Q())
	if err != nil {
		return nil, err
	}
	defer pool.ReleaseBuf(queryPayload)

	// If voting is not enabled, use original logic
	if f.args.Voting == nil || f.args.Voting.Threshold <= 0 {
		return f.exchangeOriginal(ctx, qCtx, us, queryPayload)
	}

	// Voting mode: collect multiple responses and vote
	return f.exchangeWithVoting(ctx, qCtx, us, queryPayload)
}

// Original exchange logic (non-voting)
func (f *Forward) exchangeOriginal(ctx context.Context, qCtx *query_context.Context, us []*upstreamWrapper, queryPayload *[]byte) (*dns.Msg, error) {
	concurrent := f.args.Concurrent
	if concurrent <= 0 {
		concurrent = 1
	}
	if concurrent > maxConcurrentQueries {
		concurrent = maxConcurrentQueries
	}

	type res struct {
		r   *dns.Msg
		err error
	}

	resChan := make(chan res)
	done := make(chan struct{})
	defer close(done)

	r := rand.IntN(len(us))
	for i := 0; i < concurrent; i++ {
		u := us[(r+i)%len(us)]
		qc := copyPayload(queryPayload)
		go func(uqid uint32, question dns.Question) {
			defer pool.ReleaseBuf(qc)
			upstreamCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()

			var r *dns.Msg
			respPayload, err := u.ExchangeContext(upstreamCtx, *qc)
			if err != nil {
				f.logger.Warn(
					"upstream error",
					zap.Uint32("uqid", uqid),
					zap.String("qname", question.Name),
					zap.Uint16("qclass", question.Qclass),
					zap.Uint16("qtype", question.Qtype),
					zap.String("upstream", u.name()),
					zap.Error(err),
				)
			} else {
				r = new(dns.Msg)
				err = r.Unpack(*respPayload)
				pool.ReleaseBuf(respPayload)
				if err != nil {
					r = nil
				}
			}
			select {
			case resChan <- res{r: r, err: err}:
			case <-done:
			}
		}(qCtx.Id(), qCtx.QQuestion())
	}

	for i := 0; i < concurrent; i++ {
		select {
		case res := <-resChan:
			r, err := res.r, res.err
			if err != nil {
				continue
			}
			if i < concurrent-1 && r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
				continue
			}
			return r, nil
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
	return nil, errors.New("all upstream servers failed")
}

// Voting response type (extend original res with timing)
// Exchange with voting consensus
func (f *Forward) exchangeWithVoting(ctx context.Context, qCtx *query_context.Context, us []*upstreamWrapper, queryPayload *[]byte) (*dns.Msg, error) {
	type res struct {
		r      *dns.Msg
		err    error
		origin string // upstream name for logging
	}
	threshold := f.args.Voting.Threshold
	votingTimeout := time.Duration(f.args.Voting.Timeout) * time.Millisecond
	if votingTimeout <= 0 {
		votingTimeout = queryTimeout
	}

	// Initial concurrent requests
	concurrent := f.args.Concurrent
	if concurrent <= 0 {
		concurrent = 1
	}
	if concurrent > maxConcurrentQueries {
		concurrent = maxConcurrentQueries
	}
	if threshold > len(us) {
		threshold = len(us)
	}

	resChan := make(chan res, len(us))
	done := make(chan struct{})
	defer close(done)

	sendRequest := func(u *upstreamWrapper) {
		qc := copyPayload(queryPayload)
		go func(uqid uint32, question dns.Question, upstreamName string) {
			defer pool.ReleaseBuf(qc)
			upstreamCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
			defer cancel()

			var r *dns.Msg
			respPayload, err := u.ExchangeContext(upstreamCtx, *qc)
			if err != nil {
				f.logger.Warn(
					"upstream error",
					zap.Uint32("uqid", uqid),
					zap.String("qname", question.Name),
					zap.Uint16("qclass", question.Qclass),
					zap.Uint16("qtype", question.Qtype),
					zap.String("upstream", upstreamName),
					zap.Error(err),
				)
			} else {
				r = new(dns.Msg)
				err = r.Unpack(*respPayload)
				pool.ReleaseBuf(respPayload)
				if err != nil {
					r = nil
				}
			}
			select {
			case resChan <- res{r: r, err: err, origin: upstreamName}:
			case <-done:
			}
		}(qCtx.Id(), qCtx.QQuestion(), u.name())
	}

	// Send initial concurrent requests
	r := rand.IntN(len(us))
	sent := 0
	for i := 0; i < concurrent && sent < len(us); i++ {
		sendRequest(us[(r+i)%len(us)])
		sent++
	}

	// Voting: use map to count IPs incrementally
	ipCounts := make(map[string]int)
	ipResponse := make(map[string]*dns.Msg)
	var responses []res
	timeoutCtx, cancel := context.WithTimeout(ctx, votingTimeout)
	defer cancel()

	// Collect responses
	for {
		select {
		case res := <-resChan:
			if res.err == nil && res.r != nil {
				responses = append(responses, res)
				// Debug: log received response
				var ips []string
				if res.r.Answer != nil {
					// Only compare the first IP for consensus (simpler and more effective)
					for i, ans := range res.r.Answer {
						if a, ok := ans.(*dns.A); ok {
							ip := a.A.String()
							ips = append(ips, ip)
							// Only count the first IP for voting
							if i == 0 {
								ipCounts[ip]++
								if ipCounts[ip] == 1 {
									ipResponse[ip] = res.r
								}
								// Check if threshold reached
								if ipCounts[ip] >= threshold {
									f.logger.Debug("voting consensus reached",
										zap.String("qname", qCtx.QQuestion().Name),
										zap.String("upstream", res.origin),
										zap.String("ip", ip),
										zap.Int("count", ipCounts[ip]),
										zap.Int("threshold", threshold),
									)
									return res.r, nil
								}
							}
						}
					}
				}
				f.logger.Debug("voting received response",
					zap.String("qname", qCtx.QQuestion().Name),
					zap.String("upstream", res.origin),
					zap.Strings("ips", ips),
					zap.Any("ip_counts", ipCounts),
					zap.Int("threshold", threshold),
				)
			}
			// Send more requests if available
			if sent < len(us) {
				sendRequest(us[(r+sent)%len(us)])
				sent++
			}
		case <-timeoutCtx.Done():
			// Timeout, return first successful response
			for _, r := range responses {
				if r.r != nil {
					return r.r, nil
				}
			}
			return nil, errors.New("all upstream servers failed")
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
	}
}

func quickSetup(bq sequence.BQ, s string) (any, error) {
	args := new(Args)
	args.Concurrent = maxConcurrentQueries
	for _, u := range strings.Fields(s) {
		args.Upstreams = append(args.Upstreams, UpstreamConfig{Addr: u})
	}
	return NewForward(args, Opts{Logger: bq.L()})
}
