// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"log/slog"
	"slices"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func (s *BgpServer) rtcDeferralCallback(p *peer) func() {
	conf := p.fsm.pConf.ReadOnly()
	address, session := conf.State.NeighborAddress, p.peerInfo.Load()
	return func() {
		_ = s.mgmtOperation(func() error {
			conf := p.fsm.pConf.ReadOnly()
			if s.neighborMap[address] != p || p.peerInfo.Load() != session || conf.GracefulRestart.State.LocalRestarting ||
				conf.State.SessionState != oc.SESSION_STATE_ESTABLISHED || !p.getRtcEORWait() {
				return nil
			}
			return s.softResetOut(address.String(), bgp.Family(0), true)
		}, false)
	}
}

// RFC 4724 section 4.2 and RFC 9494 section 4.2 require dropping retained
// stale routes if the relevant capability, family, or forwarding bit is lost.
func (s *BgpServer) reconcilePeerRestart(p *peer) {
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadOnly()
	if !conf.GracefulRestart.State.PeerRestarting {
		p.fsm.lock.Unlock()
		return
	}
	grPreserved := make(map[bgp.Family]bool)
	llgrPreserved := make(map[bgp.Family]bool)
	gr := p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART]
	if conf.GracefulRestart.Config.Enabled && len(gr) > 0 {
		for _, t := range gr[len(gr)-1].(*bgp.CapGracefulRestart).Tuples {
			grPreserved[bgp.NewFamily(t.AFI, t.SAFI)] = t.Flags&0x80 != 0
		}
		llgr := p.fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
		if conf.GracefulRestart.Config.LongLivedEnabled && len(llgr) > 0 {
			for _, t := range llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart).Tuples {
				llgrPreserved[bgp.NewFamily(t.AFI, t.SAFI)] = t.Flags&0x80 != 0
			}
		}
	}
	negotiated := p.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)
	var drop []bgp.Family
	for _, a := range conf.AfiSafis {
		family := a.State.Family
		preserved := grPreserved[family]
		if a.LongLivedGracefulRestart.State.Running {
			preserved = llgrPreserved[family]
		}
		if _, ok := negotiated[family]; !ok || !preserved {
			drop = append(drop, family)
		}
	}
	p.fsm.lock.Unlock()
	s.finishPeerRestartFamilies(p, drop)
}

// RFC 4724 section 4.2 and RFC 9494 section 4.2: EOR removes remaining
// stale routes and ends the LLGR timer for that address family.
func (s *BgpServer) finishPeerRestartFamilies(p *peer, families []bgp.Family) {
	paths := p.adjRibIn.DropStale(families)
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	pending := false
	for i := range conf.AfiSafis {
		a := &conf.AfiSafis[i]
		if slices.Contains(families, a.State.Family) {
			a.MpGracefulRestart.State.Running = false
			a.LongLivedGracefulRestart.State.Running = false
			if ch := p.llgrEndChs[a.State.Family]; ch != nil {
				close(ch)
				delete(p.llgrEndChs, a.State.Family)
			}
		}
		pending = pending || a.MpGracefulRestart.State.Running || a.LongLivedGracefulRestart.State.Running
	}
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
	if !pending {
		p.stopPeerRestarting()
	}
	if len(paths) > 0 {
		p.fsm.logger.Debug("withdraw stale routes", slog.Any("Families", families), slog.Int("Numbers", len(paths)))
		s.propagateUpdate(p, paths)
	}
}
