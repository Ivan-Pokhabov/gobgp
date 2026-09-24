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
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func runLocalRestartTestOp(t *testing.T, s *BgpServer, f func()) {
	t.Helper()
	require.NoError(t, s.mgmtOperation(func() error { f(); return nil }, false))
}

func newLocalRestartTestServer(t *testing.T) *BgpServer {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{Global: &api.Global{Asn: 65000, RouterId: "192.0.2.254", ListenPort: -1}}))
	t.Cleanup(func() {
		var peers []*peer
		runLocalRestartTestOp(t, s, func() {
			for _, p := range s.neighborMap {
				peers = append(peers, p)
				p.stopPeerRestarting()
			}
			clear(s.neighborMap)
		})
		s.Stop()
		for _, p := range peers {
			cleanInfiniteChannel(p.fsm.outgoingCh)
		}
	})
	return s
}

// Called through runLocalRestartTestOp, like addNeighbor.
func newLocalRestartTestPeer(t *testing.T, s *BgpServer, addr string) *peer {
	p := newPeerandInfo(t, 65000, 65001, addr, s.globalRib)
	conf := p.fsm.pConf.ReadCopy()
	conf.GracefulRestart.Config.Enabled = true
	conf.GracefulRestart.Config.DeferralTime = 60
	conf.GracefulRestart.State.Enabled = true
	conf.GracefulRestart.State.LocalRestarting = true
	conf.AfiSafis = []oc.AfiSafi{{
		State: oc.AfiSafiState{Family: bgp.RF_IPv4_UC},
		MpGracefulRestart: oc.MpGracefulRestart{
			Config: oc.MpGracefulRestartConfig{Enabled: true},
			State:  oc.MpGracefulRestartState{Enabled: true, Received: true},
		},
	}}
	p.fsm.pConf.Update(&conf)
	p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(false, false, 60, nil)}
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: bgp.BGP_ADD_PATH_NONE})
	setLocalRestartTestState(p, bgp.BGP_FSM_ESTABLISHED)
	s.neighborMap[conf.State.NeighborAddress] = p
	return p
}

func setLocalRestartTestState(p *peer, state bgp.FSMState) {
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.State.SessionState = oc.IntToSessionStateMap[int(state)]
	p.fsm.pConf.Update(&conf)
	p.fsm.state.Store(state)
	p.fsm.lock.Unlock()
}

func markTestEORReceived(p *peer) {
	p.fsm.lock.Lock()
	conf := p.fsm.pConf.ReadCopy()
	conf.AfiSafis[0].MpGracefulRestart.State.EndOfRibReceived = true
	p.fsm.pConf.Update(&conf)
	p.fsm.lock.Unlock()
}

func addLocalRestartTestRoute(t *testing.T, s *BgpServer) *table.Path {
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
	require.NoError(t, err)
	nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.254"))
	require.NoError(t, err)
	path := table.NewPath(bgp.RF_IPv4_UC, nil, bgp.PathNLRI{NLRI: nlri}, false,
		[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
	s.globalRib.Update(path)
	return path
}

func requireLocalRestartDump(t *testing.T, p *peer, withRoute bool) {
	t.Helper()
	select {
	case msg := <-p.fsm.outgoingCh.Out():
		paths := msg.(*fsmOutgoingMsg).Paths
		if withRoute {
			require.Len(t, paths, 2)
			require.Equal(t, "203.0.113.0/24", paths[0].GetNlri().String())
		} else {
			require.Len(t, paths, 1)
		}
		require.True(t, paths[len(paths)-1].IsEOR())
	case <-time.After(time.Second):
		t.Fatal("missing initial dump")
	}
}

func TestLocalRestartEORCapabilityPredicate(t *testing.T) {
	s := newLocalRestartTestServer(t)
	runLocalRestartTestOp(t, s, func() {
		p := newLocalRestartTestPeer(t, s, "192.0.2.1")
		conf := p.fsm.pConf.ReadCopy()
		conf.GracefulRestart.State.LocalRestarting = false // already released peer
		p.fsm.pConf.Update(&conf)
		require.False(t, p.localRestartEORWaitComplete(), "helper-only GR with no tuples still promises EOR")
		p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(true, false, 60, nil)}
		require.True(t, p.localRestartEORWaitComplete(), "R-bit excludes an already released peer after reconnect")
		require.False(t, p.fsm.pConf.ReadOnly().AfiSafis[0].MpGracefulRestart.State.EndOfRibReceived, "exclusion is not an actual EOR")
		p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(false, false, 60, []*bgp.CapGracefulRestartTuple{bgp.NewCapGracefulRestartTuple(bgp.RF_IPv6_UC, true)})}
		markTestEORReceived(p)
		require.True(t, p.localRestartEORWaitComplete(), "a tuple without negotiated MP does not block")
		delete(p.fsm.capMap, bgp.BGP_CAP_GRACEFUL_RESTART)
		require.True(t, p.localRestartEORWaitComplete())
	})
}

func TestLocalRestartSecondaryDumpEOR(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "populated"}[populated], func(t *testing.T) {
			s := newLocalRestartTestServer(t)
			var p *peer
			runLocalRestartTestOp(t, s, func() {
				p = newLocalRestartTestPeer(t, s, "192.0.2.1")
				conf := p.fsm.pConf.ReadCopy()
				conf.RouteServer.Config.RouteServerClient = true
				conf.RouteServer.Config.SecondaryRoute = true
				p.fsm.pConf.Update(&conf)
				s.rsRib = s.globalRib
				if populated {
					addLocalRestartTestRoute(t, s)
				}
				markTestEORReceived(p)
				setLocalRestartTestState(p, bgp.BGP_FSM_OPENCONFIRM)
			})
			s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED, StateReason: &fsmStateReason{Type: fsmNewConnection}})
			requireLocalRestartDump(t, p, populated)
		})
	}
}

func addRetainedTestRoutes(t *testing.T, p *peer, llgr bool) {
	t.Helper()
	p.adjRibIn = table.NewAdjRib(p.fsm.logger, []bgp.Family{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC})
	conf := p.fsm.pConf.ReadCopy()
	conf.GracefulRestart.State.PeerRestarting = true
	conf.GracefulRestart.Config.LongLivedEnabled = llgr
	conf.AfiSafis = nil
	families := map[bgp.Family]string{bgp.RF_IPv4_UC: "203.0.113.0/24", bgp.RF_IPv6_UC: "2001:db8::/64"}
	for family, prefix := range families {
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
		require.NoError(t, err)
		path := table.NewPath(family, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Now(), false)
		path.MarkStale(true)
		p.adjRibIn.Update([]*table.Path{path})
		conf.AfiSafis = append(conf.AfiSafis, oc.AfiSafi{
			State:                    oc.AfiSafiState{Family: family},
			MpGracefulRestart:        oc.MpGracefulRestart{State: oc.MpGracefulRestartState{Running: !llgr}},
			LongLivedGracefulRestart: oc.LongLivedGracefulRestart{State: oc.LongLivedGracefulRestartState{Running: llgr}},
		})
	}
	p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: 0, bgp.RF_IPv6_UC: 0})
	p.fsm.pConf.Update(&conf)
}

func TestPeerRestartEORPerFamily(t *testing.T) {
	s := newLocalRestartTestServer(t)
	var p *peer
	var ended, pending chan struct{}
	runLocalRestartTestOp(t, s, func() {
		p = newLocalRestartTestPeer(t, s, "192.0.2.1")
		addRetainedTestRoutes(t, p, true)
		ended, pending = make(chan struct{}), make(chan struct{})
		p.llgrEndChs = map[bgp.Family]chan struct{}{bgp.RF_IPv4_UC: ended, bgp.RF_IPv6_UC: pending}
		p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(true, false, 60, nil)}
	})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: bgp.NewEndOfRib(bgp.RF_IPv4_UC), timestamp: time.Now()})
	runLocalRestartTestOp(t, s, func() {
		require.Zero(t, p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC}))
		require.Equal(t, 1, p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv6_UC}))
		require.True(t, p.fsm.pConf.ReadOnly().GracefulRestart.State.PeerRestarting)
		select {
		case <-ended:
		default:
			t.Fatal("IPv4 LLST not stopped")
		}
		select {
		case <-pending:
			t.Fatal("IPv6 LLST stopped prematurely")
		default:
		}
	})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: bgp.NewEndOfRib(bgp.RF_IPv6_UC), timestamp: time.Now()})
	runLocalRestartTestOp(t, s, func() { require.False(t, p.fsm.pConf.ReadOnly().GracefulRestart.State.PeerRestarting) })
}

func TestPeerRestartReconnectCapabilities(t *testing.T) {
	for _, mode := range []string{"no-gr", "missing-af", "f-clear", "llgr-f-clear", "preserved", "llgr-preserved"} {
		t.Run(mode, func(t *testing.T) {
			s := newLocalRestartTestServer(t)
			runLocalRestartTestOp(t, s, func() {
				p := newLocalRestartTestPeer(t, s, "192.0.2.1")
				llgr := mode == "llgr-f-clear" || mode == "llgr-preserved"
				addRetainedTestRoutes(t, p, llgr)
				gr := bgp.NewCapGracefulRestart(true, false, 60, []*bgp.CapGracefulRestartTuple{bgp.NewCapGracefulRestartTuple(bgp.RF_IPv4_UC, mode != "f-clear")})
				p.fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{gr}
				if mode == "no-gr" {
					delete(p.fsm.capMap, bgp.BGP_CAP_GRACEFUL_RESTART)
				}
				if mode == "missing-af" {
					gr.Tuples = nil
				}
				if llgr {
					p.fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART] = []bgp.ParameterCapabilityInterface{bgp.NewCapLongLivedGracefulRestart([]*bgp.CapLongLivedGracefulRestartTuple{bgp.NewCapLongLivedGracefulRestartTuple(bgp.RF_IPv4_UC, mode == "llgr-preserved", 60)})}
				}
				s.reconcilePeerRestart(p)
				want := 0
				if mode == "preserved" || mode == "llgr-preserved" {
					want = 1
				}
				require.Equal(t, want, p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC}))
				require.Zero(t, p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv6_UC}))
				require.Equal(t, want == 1, p.fsm.pConf.ReadOnly().GracefulRestart.State.PeerRestarting)
			})
		})
	}
}

func TestRTCDeferralIgnoresOldPeerAndSession(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "reconnect", true: "replacement"}[replacement], func(t *testing.T) {
			s := newLocalRestartTestServer(t)
			var oldCallback, currentCallback func()
			var current *peer
			configureRTC := func(p *peer) {
				conf := p.fsm.pConf.ReadCopy()
				conf.GracefulRestart.State.LocalRestarting = false
				conf.AfiSafis = append(conf.AfiSafis, oc.AfiSafi{
					Config: oc.AfiSafiConfig{AfiSafiName: oc.AFI_SAFI_TYPE_RTC},
					State:  oc.AfiSafiState{Family: bgp.RF_RTC_UC},
				})
				p.fsm.pConf.Update(&conf)
				p.fsm.familyMap.Store(map[bgp.Family]bgp.BGPAddPathMode{bgp.RF_IPv4_UC: 0, bgp.RF_RTC_UC: 0})
				p.setRtcEORWait(true)
			}
			runLocalRestartTestOp(t, s, func() {
				p := newLocalRestartTestPeer(t, s, "192.0.2.1")
				configureRTC(p)
				oldCallback = s.rtcDeferralCallback(p)
				current = p
				if replacement {
					current = newLocalRestartTestPeer(t, s, "192.0.2.1")
					configureRTC(current)
					cleanInfiniteChannel(p.fsm.outgoingCh)
				} else {
					info := *p.peerInfo.Load()
					p.peerInfo.Store(&info) // new Established session, even if counters were reset
				}
				currentCallback = s.rtcDeferralCallback(current)
			})
			oldCallback()
			require.True(t, current.getRtcEORWait(), "old session must not release the current RTC wait")
			currentCallback()
			require.False(t, current.getRtcEORWait(), "current session timeout still releases RTC wait")
		})
	}
}

func TestLocalRestartOpenNegotiationDoesNotInventEOR(t *testing.T) {
	s := newLocalRestartTestServer(t)
	runLocalRestartTestOp(t, s, func() {
		p := newLocalRestartTestPeer(t, s, "192.0.2.1")
		conn := NewMockConnection()
		conn.SetRemoteAddr("192.0.2.1")
		defer conn.Close()
		p.fsm.conn = conn
		conf := p.fsm.pConf.ReadCopy()
		conf.AfiSafis[0].Config.AfiSafiName = oc.AFI_SAFI_TYPE_IPV4_UNICAST
		p.fsm.pConf.Update(&conf)
		open, err := bgp.NewBGPOpenMessage(65001, 90, netip.MustParseAddr("192.0.2.1"), []bgp.OptionParameterInterface{
			bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC), bgp.NewCapGracefulRestart(true, false, 60, nil)}),
		})
		require.NoError(t, err)
		p.fsm.recvOpen = open
		p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, &fsmStateReason{Type: fsmNewConnection})
		require.True(t, p.localRestartEORWaitComplete())
		require.False(t, p.fsm.pConf.ReadOnly().AfiSafis[0].MpGracefulRestart.State.EndOfRibReceived)
		// The next session has no GR: negotiated state must not leak across sessions.
		open, err = bgp.NewBGPOpenMessage(65001, 90, netip.MustParseAddr("192.0.2.1"), nil)
		require.NoError(t, err)
		p.fsm.recvOpen = open
		p.fsm.stateChange(bgp.BGP_FSM_ESTABLISHED, &fsmStateReason{Type: fsmNewConnection})
		require.False(t, p.fsm.pConf.ReadOnly().GracefulRestart.State.Enabled)
	})
}

func TestPeerRestartLLGRExpiryAcrossReset(t *testing.T) {
	for _, synchronized := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-eor", true: "after-eor"}[synchronized], func(t *testing.T) {
			s := newLocalRestartTestServer(t)
			var p *peer
			var refreshed *table.Path
			runLocalRestartTestOp(t, s, func() {
				p = newLocalRestartTestPeer(t, s, "192.0.2.1")
				conf := p.fsm.pConf.ReadCopy()
				conf.GracefulRestart.State.LocalRestarting = false
				conf.GracefulRestart.State.PeerRestarting = true
				conf.GracefulRestart.State.LongLivedEnabled = true
				conf.GracefulRestart.Config.LongLivedEnabled = true
				conf.AfiSafis[0].Config.AfiSafiName = oc.AFI_SAFI_TYPE_IPV4_UNICAST
				conf.AfiSafis[0].MpGracefulRestart.State.Running = true
				conf.AfiSafis[0].LongLivedGracefulRestart.State = oc.LongLivedGracefulRestartState{Enabled: true, Received: true, PeerRestartTime: 1}
				p.fsm.pConf.Update(&conf)
				setLocalRestartTestState(p, bgp.BGP_FSM_ACTIVE)
				for _, prefix := range []string{"203.0.113.0/24", "203.0.114.0/24"} {
					nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
					require.NoError(t, err)
					nh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr("192.0.2.1"))
					require.NoError(t, err)
					path := table.NewPath(bgp.RF_IPv4_UC, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false,
						[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
					path.MarkStale(true)
					p.adjRibIn.Update([]*table.Path{path})
					// A received UPDATE has independent originInfo; Clone shares the stale flag.
					refreshed = table.NewPath(bgp.RF_IPv4_UC, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false,
						[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0), nh}, time.Now(), false)
				}
			})
			// Expiry of the ordinary restart period starts the LLST.
			s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE,
				StateReason: &fsmStateReason{Type: fsmRestartTimerExpired}})
			runLocalRestartTestOp(t, s, func() {
				setLocalRestartTestState(p, bgp.BGP_FSM_ESTABLISHED)
				p.adjRibIn.Update([]*table.Path{refreshed})
			})
			require.Eventually(t, func() bool {
				return p.fsm.pConf.ReadOnly().AfiSafis[0].LongLivedGracefulRestart.State.PeerRestartTimerExpired
			}, 3*time.Second, 10*time.Millisecond)
			var paths []*table.Path
			runLocalRestartTestOp(t, s, func() {
				paths = p.adjRibIn.PathList([]bgp.Family{bgp.RF_IPv4_UC}, false)
			})
			require.Len(t, paths, 1)
			require.Equal(t, refreshed.GetNlri().String(), paths[0].GetNlri().String())
			require.False(t, paths[0].IsStale())
			require.False(t, p.fsm.pConf.ReadOnly().GracefulRestart.State.PeerRestarting)
			if synchronized {
				s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: bgp.NewEndOfRib(bgp.RF_IPv4_UC), timestamp: time.Now()})
			}
			s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ACTIVE,
				StateReason: &fsmStateReason{Type: fsmGracefulRestart}})
			var retained int
			runLocalRestartTestOp(t, s, func() {
				retained = p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC})
			})
			if synchronized {
				require.Equal(t, 1, retained, "EOR permits retention on a later restart")
			} else {
				require.Zero(t, retained, "reset after LLST expiry but before EOR must remove refreshed routes immediately")
			}
			s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE,
				StateReason: &fsmStateReason{Type: fsmRestartTimerExpired}})
			var restarted bool
			runLocalRestartTestOp(t, s, func() { restarted = p.llgrEndChs[bgp.RF_IPv4_UC] != nil })
			require.Equal(t, synchronized, restarted, "only EOR permits another LLST")
		})
	}
}

func TestLocalRestartSecondaryReconnectDump(t *testing.T) {
	s := newLocalRestartTestServer(t)
	var p *peer
	runLocalRestartTestOp(t, s, func() {
		p = newLocalRestartTestPeer(t, s, "192.0.2.1")
		conf := p.fsm.pConf.ReadCopy()
		conf.RouteServer.Config.RouteServerClient = true
		conf.RouteServer.Config.SecondaryRoute = true
		p.fsm.pConf.Update(&conf)
		s.rsRib = s.globalRib
		addLocalRestartTestRoute(t, s)
		markTestEORReceived(p)
		setLocalRestartTestState(p, bgp.BGP_FSM_OPENCONFIRM)
	})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED, StateReason: &fsmStateReason{Type: fsmNewConnection}})
	requireLocalRestartDump(t, p, true)
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE,
		StateReason: &fsmStateReason{Type: fsmReadFailed}})
	runLocalRestartTestOp(t, s, func() { setLocalRestartTestState(p, bgp.BGP_FSM_OPENCONFIRM) })
	// The callback runs before atomic Established is published. The RIB has not changed.
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ESTABLISHED,
		StateReason: &fsmStateReason{Type: fsmNewConnection}})
	requireLocalRestartDump(t, p, true)
}

func TestPeerRestartLLGRNewTimerAfterOneAFEOR(t *testing.T) {
	s := newLocalRestartTestServer(t)
	var p *peer
	var refreshed *table.Path
	runLocalRestartTestOp(t, s, func() {
		p = newLocalRestartTestPeer(t, s, "192.0.2.1")
		addRetainedTestRoutes(t, p, false)
		conf := p.fsm.pConf.ReadCopy()
		conf.GracefulRestart.State.LocalRestarting = false
		conf.GracefulRestart.Config.LongLivedEnabled = true
		conf.GracefulRestart.State.LongLivedEnabled = true
		for i := range conf.AfiSafis {
			a := &conf.AfiSafis[i]
			a.Config.AfiSafiName = oc.AfiSafiType(bgp.AddressFamilyNameMap[a.State.Family])
			a.MpGracefulRestart.State.Enabled = true
			a.MpGracefulRestart.State.Received = true
			duration := uint32(60)
			if a.State.Family == bgp.RF_IPv4_UC {
				duration = 1
			}
			a.LongLivedGracefulRestart.State = oc.LongLivedGracefulRestartState{Enabled: true, Received: true, PeerRestartTime: duration}
		}
		p.fsm.pConf.Update(&conf)
		setLocalRestartTestState(p, bgp.BGP_FSM_ACTIVE)
		nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix("203.0.113.0/24"))
		require.NoError(t, err)
		refreshed = table.NewPath(bgp.RF_IPv4_UC, p.peerInfo.Load(), bgp.PathNLRI{NLRI: nlri}, false,
			[]bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(0)}, time.Now(), false)
	})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE,
		StateReason: &fsmStateReason{Type: fsmRestartTimerExpired}})
	var oldV4, oldV6 chan struct{}
	runLocalRestartTestOp(t, s, func() {
		oldV4, oldV6 = p.llgrEndChs[bgp.RF_IPv4_UC], p.llgrEndChs[bgp.RF_IPv6_UC]
		setLocalRestartTestState(p, bgp.BGP_FSM_ESTABLISHED)
		p.adjRibIn.Update([]*table.Path{refreshed})
	})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgBGPMessage, MsgData: bgp.NewEndOfRib(bgp.RF_IPv4_UC), timestamp: time.Now()})
	select {
	case <-oldV4:
	default:
		t.Fatal("synchronized IPv4 timer was not cancelled")
	}
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_ACTIVE,
		StateReason: &fsmStateReason{Type: fsmGracefulRestart}})
	s.handleFSMMessage(p, &fsmMsg{MsgType: fsmMsgStateChange, MsgData: bgp.BGP_FSM_IDLE,
		StateReason: &fsmStateReason{Type: fsmRestartTimerExpired}})
	var newV4, newV6 chan struct{}
	runLocalRestartTestOp(t, s, func() {
		newV4, newV6 = p.llgrEndChs[bgp.RF_IPv4_UC], p.llgrEndChs[bgp.RF_IPv6_UC]
	})
	require.NotNil(t, newV4, "synchronized AF needs its own new LLST")
	require.NotEqual(t, oldV4, newV4)
	require.Equal(t, oldV6, newV6, "unsynchronized AF must retain its original LLST")
	require.Eventually(t, func() bool {
		return p.fsm.pConf.ReadOnly().GetAfiSafi(bgp.RF_IPv4_UC).LongLivedGracefulRestart.State.PeerRestartTimerExpired
	}, 3*time.Second, 10*time.Millisecond)
	var v4, v6 int
	runLocalRestartTestOp(t, s, func() {
		v4 = p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv4_UC})
		v6 = p.adjRibIn.Count([]bgp.Family{bgp.RF_IPv6_UC})
	})
	require.Zero(t, v4)
	require.Equal(t, 1, v6)
}
