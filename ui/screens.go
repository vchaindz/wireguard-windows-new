/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// A statusLook is how the state of a tunnel is presented: colors, icon and wording.
type statusLook struct {
	accent, background rgb
	icon               iconKind
	dashed             bool
	glyph              glyphKind
	primary            buttonStyle
	title              string
	// short is the one-line status shown next to a tunnel name, in the color shortColor.
	short      string
	shortColor rgb
	// message explains a problem, if there is one.
	message     string
	messageKind noticeKind
}

func lookFor(entry *tunnelEntry) statusLook {
	look := statusLook{accent: theme.muted, background: theme.panel, icon: iconShield, glyph: glyphOff, primary: buttonGreen, shortColor: theme.textDim}
	if entry == nil {
		look.title = l18n.Sprintf("Not connected")
		look.short = l18n.Sprintf("No tunnel is active")
		return look
	}
	switch entry.state {
	case manager.TunnelStarting:
		look.accent, look.glyph = theme.textDim, glyphBusy
		look.title = l18n.Sprintf("Activating…")
		look.short = look.title
	case manager.TunnelStopping:
		look.accent, look.glyph = theme.textDim, glyphBusy
		look.title = l18n.Sprintf("Deactivating…")
		look.short = look.title
	case manager.TunnelStarted:
		look.accent, look.background, look.glyph = theme.green, theme.greenBg, glyphOn
		switch entry.health {
		case manager.TunnelHealthConnected:
			look.icon = iconShieldCheck
			look.title = l18n.Sprintf("Connected")
			look.short, look.shortColor = look.title, theme.green
		case manager.TunnelHealthWaitingForPeer:
			look.accent, look.background, look.glyph, look.primary = theme.amber, theme.amberBg, glyphWarning, buttonAmber
			look.icon, look.dashed = iconClock, true
			look.title = l18n.Sprintf("Waiting for peer")
			look.short, look.shortColor = l18n.Sprintf("Peer does not answer · network unaffected"), theme.amberSoft
			look.message = l18n.Sprintf("Routes have not been applied, so the rest of your network is unaffected. Check the endpoint, the keys and your network.")
		case manager.TunnelHealthNoConnection:
			look.accent, look.background, look.glyph, look.primary = theme.amber, theme.amberBg, glyphWarning, buttonAmber
			look.icon = iconShieldCross
			look.title = l18n.Sprintf("No connection")
			look.short, look.shortColor = l18n.Sprintf("Peer does not answer"), theme.amberSoft
			look.message = l18n.Sprintf("The peer does not answer. Check the endpoint, the keys and your network.")
		case manager.TunnelHealthNoConnectionNetworkBlocked:
			look.accent, look.background, look.glyph, look.primary = theme.red, theme.redBg, glyphAlert, buttonRed
			look.icon = iconShieldCross
			look.title = l18n.Sprintf("Network cut off")
			look.short, look.shortColor = look.title, theme.redSoft
			look.message, look.messageKind = l18n.Sprintf("This tunnel takes over all network traffic, but its peer does not answer. Nothing gets through until it answers or you deactivate the tunnel."), noticeRed
		default:
			look.title = l18n.Sprintf("Active")
			look.short = l18n.Sprintf("Active · connection not verified yet")
		}
	case manager.TunnelStopped:
		look.title = l18n.Sprintf("Inactive")
		look.short = look.title
	default:
		look.title = l18n.Sprintf("Unknown state")
		look.short = look.title
	}
	return look
}

// connectionWarning is the text about the stability of a connection, if there is something to say.
func connectionWarning(entry *tunnelEntry) (title, text string) {
	if entry.state != manager.TunnelStarted {
		return "", ""
	}
	if entry.conflictSuspected {
		return l18n.Sprintf("Key used elsewhere"), l18n.Sprintf("Another device appears to be using this tunnel's key, which breaks connections on both. Give each device its own key pair.")
	}
	if entry.unstable {
		return "", l18n.Sprintf("The connection is unstable: it was lost and re-established recently.")
	}
	if port := entry.metrics.ReplacedListenPort; port != 0 {
		return l18n.Sprintf("Listen port %d does not work here", port), l18n.Sprintf("No reply arrived on the listen port of this tunnel, so it is connected from a random port instead. The router or another device on this network may be using port %d. Remove ListenPort from the configuration or choose another port.", port)
	}
	return "", ""
}

func joinAddresses[T interface{ String() string }](addresses []T) string {
	parts := make([]string, len(addresses))
	for i := range addresses {
		parts[i] = addresses[i].String()
	}
	return strings.Join(parts, l18n.EnumerationSeparator())
}

// latestHandshake returns the most recent handshake of any peer, and the traffic of all peers.
func trafficOf(config *conf.Config) (handshake conf.HandshakeTime, rx, tx conf.Bytes) {
	for i := range config.Peers {
		peer := &config.Peers[i]
		if peer.LastHandshakeTime > handshake {
			handshake = peer.LastHandshakeTime
		}
		rx += peer.RxBytes
		tx += peer.TxBytes
	}
	return
}

// busyPulsePeriod is how long one breath of the status ring takes while a tunnel is being switched.
const busyPulsePeriod = 1600 * time.Millisecond

const (
	screenPadding = 28
	footerHeight  = 80
	headerHeight  = 52
)

// buildStatus draws the main screen: the state of the active tunnel on top, the other tunnels below.
func (mtw *ManageTunnelsWindow) buildStatus(s *scene, width, height float64) {
	model := mtw.model
	left, inner := float64(screenPadding), width-2*screenPadding
	y := 24.0
	top := s.mark()

	if model.updateAvailable {
		s.fillFaded(left, 14, inner, 36, 8, theme.amberBg, s.hoverAmount("update", s.hit("update", left, 14, inner, 36, func() { mtw.showScreen(screenUpdate) })))
		s.stroke(left, 14, inner, 36, 8, 1, theme.amberBorder)
		s.label(l18n.Sprintf("An Update is Available!"), fontBodyBold, theme.amberSoft, left+12, 14, inner-24, 36, textCenter)
		y += 40
	}

	now := time.Now()
	hero := model.hero()
	look := lookFor(hero)
	subtitle := look.short
	var suggestion *tunnelEntry
	if hero != nil {
		subtitle = hero.tunnel.Name
		if hero.state == manager.TunnelStarted && look.short != look.title {
			subtitle = l18n.Sprintf("%s · %s", hero.tunnel.Name, look.short)
		}
	} else if suggestion = model.suggested(); suggestion == nil {
		look.title = l18n.Sprintf("No tunnels yet")
		if IsAdmin {
			subtitle = l18n.Sprintf("Add the configuration you were given to get started.")
		} else {
			subtitle = l18n.Sprintf("There is nothing to connect to yet.")
		}
	}

	// The ring with the state icon. While a tunnel is being switched, the ring breathes slowly.
	ringX := width/2 - 56
	ringColor := look.accent
	if look.glyph == glyphBusy {
		ringColor = mix(look.accent, look.background, 0.7*s.pulse(busyPulsePeriod))
	}
	s.fill(ringX, y, 112, 112, 56, look.background)
	if look.dashed {
		s.dashedRing(ringX, y, 112, 3, 9, ringColor)
	} else {
		s.stroke(ringX, y, 112, 112, 56, 3, ringColor)
	}
	s.icon(look.icon, ringX+34, y+34, 44, ringColor)
	y += 112 + 12
	s.label(look.title, fontTitle, theme.text, left, y, inner, 38, textCenter)
	y += 38
	if hero != nil && hero.state == manager.TunnelStarted && hero.health == manager.TunnelHealthConnected && hero.config != nil {
		if handshake, _, _ := trafficOf(hero.config); !handshake.IsEmpty() {
			subtitle = l18n.Sprintf("%s · latest handshake %s", hero.tunnel.Name, formatAgo(handshakeAge(handshake, now)))
		}
	}
	// The color of the tunnel is shown as a dot before its name; the ring keeps the color of the state.
	if color, ok := heroColor(hero); ok {
		const dot, gap = 8, 8
		textWidth := math.Min(s.widthOf(subtitle, fontBody), inner-dot-gap)
		dotX := width/2 - (textWidth+dot+gap)/2
		s.fill(dotX, y+7, dot, dot, dot/2, color)
		s.label(subtitle, fontBody, theme.textDim, dotX+dot+gap, y, textWidth+2, 22, textLeft)
	} else {
		s.label(subtitle, fontBody, theme.textDim, left, y, inner, 22, textCenter)
	}
	y += 22 + 14

	// Address, traffic and quality of the active tunnel
	var heroQuality qualitySummary
	if hero != nil && hero.state == manager.TunnelStarted && hero.config != nil {
		samples := model.samples[hero.tunnel.Name]
		heroQuality = summarizeQuality(samples.seconds)
		_, rx, tx := trafficOf(hero.config)
		tiles := []tile{{l18n.Sprintf("Address"), joinAddresses(hero.config.Interface.Addresses), 0}}
		if !hero.metrics.ConnectedSince.IsZero() {
			tiles = append(tiles, tile{l18n.Sprintf("Connected for"), formatDuration(now.Sub(hero.metrics.ConnectedSince)), 0})
		}
		tiles = append(tiles, tile{l18n.Sprintf("Received"), formatBytes(uint64(rx)), 0}, tile{l18n.Sprintf("Sent"), formatBytes(uint64(tx)), 0})
		if heroQuality.hasData {
			tiles = append(tiles, tile{l18n.Sprintf("Quality"), qualityText(heroQuality), qualityColor(heroQuality)})
		}
		y += s.tiles(left, y, inner, tiles) + 8
		y += mtw.charts(s, left, y, inner, samples, now, 104, 88, false) + 6
	}

	// The main action
	switch {
	case hero != nil:
		name := hero.tunnel.Name
		style := look.primary
		if !model.canToggle() {
			style = buttonDisabled
		}
		s.button("hero-toggle", left, y, inner-104, 44, l18n.Sprintf("Deactivate"), style, func() { model.toggle(mtw, name) })
		s.button("hero-details", left+inner-96, y, 96, 44, l18n.Sprintf("Details"), buttonOutline, func() { mtw.showDetails(name) })
		y += 44
	case suggestion != nil:
		name := suggestion.tunnel.Name
		style := buttonGreen
		if !model.canToggle() {
			style = buttonDisabled
		}
		s.button("hero-toggle", left, y, inner, 44, l18n.Sprintf("Activate %s", name), style, func() { model.toggle(mtw, name) })
		y += 44
	case IsAdmin:
		// The first run: the two ways in, and what each of them is for.
		half := (inner - 8) / 2
		s.button("welcome-import", left, y, half, 44, l18n.Sprintf("Import from file"), buttonGreen, func() { model.importTunnels(mtw) })
		s.button("welcome-add", left+half+8, y, half, 44, l18n.Sprintf("Add a tunnel"), buttonOutline, func() { model.addTunnel(mtw) })
		y += 44 + 14
		help := l18n.Sprintf("Import reads .conf files, or .zip files of them, as your VPN provider or administrator hands them out. Add a tunnel opens an editor: paste a configuration you were given as text, or write a new one with a fresh key pair.")
		helpHeight := s.wrappedHeight(help, fontSmall, inner)
		s.text(help, fontSmall, theme.textDim, left, y, inner, helpHeight, textWrap|textCenter)
		y += helpHeight
	default:
		help := l18n.Sprintf("Tunnels can only be added by an administrator of this computer. Once one is added, it shows up here and you can switch it on and off.")
		helpHeight := s.wrappedHeight(help, fontSmall, inner)
		s.text(help, fontSmall, theme.textDim, left, y, inner, helpHeight, textWrap|textCenter)
		y += helpHeight
	}

	if hero != nil {
		if len(look.message) > 0 {
			y += 14
			y += s.notice(left, y, inner, look.messageKind, "", look.message)
		}
		if title, text := connectionWarning(hero); len(text) > 0 {
			y += 14
			y += s.notice(left, y, inner, noticeAmber, title, text)
		}
		if title, text := qualityWarning(hero, heroQuality); len(text) > 0 {
			y += 14
			y += s.notice(left, y, inner, noticeAmber, title, text)
		}
	}

	// The other tunnels, in a part of the screen that scrolls. When what is above them leaves too little room,
	// as with graphs and notices in a small window, the whole screen scrolls instead.
	var others []*tunnelEntry
	for i := range model.entries {
		if hero == nil || model.entries[i].tunnel != hero.tunnel {
			others = append(others, &model.entries[i])
		}
	}
	const rowHeight, rowGap, filterHeight = 56, 6, 36 + 10
	showFilter := len(others) > 0 && mtw.filterShown()
	listed := others
	if showFilter {
		listed = filterEntries(others, mtw.filter)
	}
	footerY := height - footerHeight
	listNeeds := 0.0
	if len(others) > 0 {
		listNeeds = 20 + 24 + float64(max(min(len(listed), 2), 1))*(rowHeight+rowGap) - rowGap
		if showFilter {
			listNeeds += filterHeight
		}
	}
	pageScrolls := y+listNeeds > footerY
	if pageScrolls {
		s.moveSince(top, -s.scroll, sceneRect{0, 0, width, footerY})
		y -= s.scroll
		s.setClip(0, 0, width, footerY)
	}
	if len(others) > 0 {
		y += 20
		caption := l18n.Sprintf("OTHER TUNNELS")
		if hero == nil {
			caption = l18n.Sprintf("TUNNELS")
		}
		s.label(caption, fontCaps, theme.textDim, left, y, inner, 16, textLeft)
		y += 24
		if showFilter {
			y += s.textField("filter", left, y, inner, mtw.filter, l18n.Sprintf("Filter tunnels by name"), mtw.focusFilter, func() { mtw.setFilter("") }) + 10
		}

		viewport := footerY - y
		rowY := y
		if !pageScrolls {
			s.maxScroll = float64(len(listed))*(rowHeight+rowGap) - rowGap - viewport
			s.setClip(0, y, width, viewport)
			rowY -= s.scroll
		}
		if len(listed) == 0 {
			s.label(l18n.Sprintf("No tunnel name contains “%s”", strings.TrimSpace(mtw.filter)), fontBody, theme.textDim, left, rowY, inner, rowHeight, textCenter)
			rowY += rowHeight + rowGap
		}
		for _, entry := range listed {
			name := entry.tunnel.Name
			rowLook := lookFor(entry)
			hover := s.hoverAmount("row:"+name, s.hit("row:"+name, left, rowY, inner, rowHeight, func() { mtw.showDetails(name) }))
			s.fill(left, rowY, inner, rowHeight, 8, mix(theme.panel, theme.panelHot, hover))
			s.tunnelMark(entry, left+5, rowY+12, rowHeight-24)
			s.glyph(rowLook.glyph, left+14, rowY+22)
			nameRoom := inner - 38 - 76
			if entry.settings.Favorite {
				// The star follows the name, which gives up room for it when it is long.
				nameWidth := math.Min(s.widthOf(name, fontBodyBold), nameRoom-20)
				s.label(name, fontBodyBold, theme.text, left+38, rowY+9, nameWidth+2, 20, textLeft)
				s.star(left+38+nameWidth+12, rowY+18.5, 12, theme.amberSoft)
			} else {
				s.label(name, fontBodyBold, theme.text, left+38, rowY+9, nameRoom, 20, textLeft)
			}
			status := rowLook.short
			if lastActive := lastActiveText(&entry.metrics, now); entry.state == manager.TunnelStopped && len(lastActive) > 0 {
				status = l18n.Sprintf("%s · %s", status, lastActive)
			}
			s.label(status, fontSmall, rowLook.shortColor, left+38, rowY+29, inner-38-76, 18, textLeft)
			s.toggle("toggle:"+name, left+inner-14-toggleWidth, rowY+16, entry.active(), model.canToggle(), func() { model.toggle(mtw, name) })
			rowY += rowHeight + rowGap
		}
		y = rowY - rowGap
		if !pageScrolls {
			s.clearClip()
			s.scrollThumb(width-10, footerY-viewport, viewport)
		}
	}
	if pageScrolls {
		s.maxScroll = y + s.scroll + 14 - footerY
		s.clearClip()
		s.scrollThumb(width-10, 4, footerY-8)
	}

	// The footer
	s.fill(0, footerY, width, footerHeight, 0, theme.backdrop)
	type footerButton struct {
		id, label string
		action    func()
	}
	buttons := []footerButton{{"log", l18n.Sprintf("Log"), func() { mtw.showScreen(screenLog) }}}
	// With no tunnels there is nothing to export, and adding and importing are offered above, larger.
	if IsAdmin && len(model.entries) > 0 {
		buttons = []footerButton{
			{"add", l18n.Sprintf("Add tunnel"), func() { model.addTunnel(mtw) }},
			{"import", l18n.Sprintf("Import"), func() { model.importTunnels(mtw) }},
			{"export", l18n.Sprintf("Export"), func() { model.exportTunnels(mtw) }},
			buttons[0],
		}
	}
	buttonWidth := (inner - float64(len(buttons)-1)*8) / float64(len(buttons))
	for i, button := range buttons {
		s.button(button.id, left+float64(i)*(buttonWidth+8), footerY+16, buttonWidth, 44, button.label, buttonOutline, button.action)
	}
}

// filterMinTunnels is how many tunnels the status screen lists before it offers a filter field.
const filterMinTunnels = 8

// filterEntries keeps the tunnels whose names contain the text, ignoring case and the spaces around the text.
func filterEntries(entries []*tunnelEntry, text string) []*tunnelEntry {
	text = strings.ToLower(strings.TrimSpace(text))
	if len(text) == 0 {
		return entries
	}
	var kept []*tunnelEntry
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.tunnel.Name), text) {
			kept = append(kept, entry)
		}
	}
	return kept
}

// focusFilter is what clicking the filter field does: the view gives it the focus, and it is drawn with a caret.
func (mtw *ManageTunnelsWindow) focusFilter() {
	if mtw.mainView != nil {
		mtw.mainView.Invalidate()
	}
}

// heroColor is the color of the tunnel on top of the status screen, if it has one.
func heroColor(hero *tunnelEntry) (rgb, bool) {
	if hero == nil {
		return 0, false
	}
	return tunnelColor(hero.settings.Color)
}

// A tile is a small panel with a caption and a value.
type tile struct {
	label, value string
	color        rgb
}

// tiles draws a row of tiles and returns its height. They share the width equally if each fits its share,
// in proportion to what they need if all fit together, and are put on two rows otherwise.
func (s *scene) tiles(x, y, w float64, tiles []tile) float64 {
	const gap, height, pad = 8, 54, 12
	if len(tiles) == 0 {
		return 0
	}
	needs := make([]float64, len(tiles))
	total, widest := float64(len(tiles)-1)*gap, 0.0
	for i := range tiles {
		needs[i] = max(s.widthOf(tiles[i].label, fontSmall), s.widthOf(tiles[i].value, fontBodyBold)) + 2*pad
		total += needs[i]
		widest = max(widest, needs[i])
	}
	share := (w - float64(len(tiles)-1)*gap) / float64(len(tiles))
	if widest > share && total > w && len(tiles) > 2 {
		half := (len(tiles) + 1) / 2
		return s.tiles(x, y, w, tiles[:half]) + gap + s.tiles(x, y+height+gap, w, tiles[half:])
	}
	widths := make([]float64, len(tiles))
	for i := range widths {
		widths[i] = share
		if widest > share && total <= w {
			widths[i] = needs[i] + (w-total)/float64(len(tiles))
		}
	}
	for i, tile := range tiles {
		color := tile.color
		if color == 0 {
			color = theme.text
		}
		s.fill(x, y, widths[i], height, 8, theme.panel)
		s.label(tile.label, fontSmall, theme.textDim, x+pad, y+8, widths[i]-2*pad, 18, textLeft)
		s.label(tile.value, fontBodyBold, color, x+pad, y+26, widths[i]-2*pad, 20, textLeft)
		x += widths[i] + gap
	}
	return height
}

// qualityColor is the color of the quality tile: amber if there is something to warn about.
func qualityColor(quality qualitySummary) rgb {
	if quality.poor() || quality.noReply() {
		return theme.amberSoft
	}
	return 0
}

// charts draws the choice of time range, the traffic graph and, if the range holds probes, the latency graph, and
// with events set the strip of events under them. It returns their height.
func (mtw *ManageTunnelsWindow) charts(s *scene, x, y, w float64, samples tunnelSamples, now time.Time, trafficHeight, latencyHeight float64, events bool) float64 {
	top := y
	y += s.rangeChips(x, y, mtw.timeRange, mtw.setRange) + 8
	traffic := trafficChart("chart:traffic", samples, mtw.timeRange, now, trafficHeight)
	latency := latencyChart("chart:latency", samples, mtw.timeRange, now, latencyHeight)
	if latency != nil {
		traffic.minGutter = s.chartGutter(latency)
		latency.minGutter = s.chartGutter(traffic)
	}
	y += s.chart(x, y, w, traffic)
	if latency != nil {
		y += 8 + s.chart(x, y, w, latency)
	}
	if events {
		y += 8 + s.timeline("chart:events", x, y, w, s.chartGutter(traffic), samples, mtw.timeRange, now)
	}
	return y - top
}

type detailRow struct {
	label, value string
	font         themeFont
	color        rgb
	copyable     bool
}

func interfaceRows(c *conf.Interface) []detailRow {
	rows := []detailRow{{label: l18n.Sprintf("Public key"), value: c.PrivateKey.Public().String(), font: fontMono, copyable: IsAdmin}}
	if c.ListenPort > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Listen port"), value: strconv.Itoa(int(c.ListenPort))})
	}
	if c.MTU > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("MTU"), value: strconv.Itoa(int(c.MTU))})
	}
	if len(c.Addresses) > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Addresses"), value: joinAddresses(c.Addresses)})
	}
	if len(c.DNS)+len(c.DNSSearch) > 0 {
		servers := make([]string, 0, len(c.DNS)+len(c.DNSSearch))
		for _, address := range c.DNS {
			servers = append(servers, address.String())
		}
		servers = append(servers, c.DNSSearch...)
		rows = append(rows, detailRow{label: l18n.Sprintf("DNS servers"), value: strings.Join(servers, l18n.EnumerationSeparator())})
	}
	var scriptsInUse []string
	if len(c.PreUp) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("pre-up"))
	}
	if len(c.PostUp) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("post-up"))
	}
	if len(c.PreDown) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("pre-down"))
	}
	if len(c.PostDown) > 0 {
		scriptsInUse = append(scriptsInUse, l18n.Sprintf("post-down"))
	}
	if len(scriptsInUse) > 0 {
		value := l18n.Sprintf("disabled, per policy")
		if conf.AdminBool("DangerousScriptExecution") {
			value = strings.Join(scriptsInUse, l18n.EnumerationSeparator())
		}
		rows = append(rows, detailRow{label: l18n.Sprintf("Scripts"), value: value})
	}
	if c.TableOff {
		rows = append(rows, detailRow{label: l18n.Sprintf("Table"), value: l18n.Sprintf("off")})
	}
	return rows
}

func peerRows(c *conf.Peer, connected bool) []detailRow {
	rows := []detailRow{{label: l18n.Sprintf("Public key"), value: c.PublicKey.String(), font: fontMono}}
	if !c.PresharedKey.IsZero() && IsAdmin {
		rows = append(rows, detailRow{label: l18n.Sprintf("Preshared key"), value: l18n.Sprintf("enabled")})
	}
	if len(c.AllowedIPs) > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Allowed IPs"), value: joinAddresses(c.AllowedIPs)})
	}
	if !c.Endpoint.IsEmpty() {
		rows = append(rows, detailRow{label: l18n.Sprintf("Endpoint"), value: c.Endpoint.String()})
	}
	if c.PersistentKeepalive > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Persistent keepalive"), value: strconv.Itoa(int(c.PersistentKeepalive))})
	}
	if !c.LastHandshakeTime.IsEmpty() {
		row := detailRow{label: l18n.Sprintf("Latest handshake"), value: formatAgo(handshakeAge(c.LastHandshakeTime, time.Now()))}
		if connected {
			row.color = theme.green
		}
		rows = append(rows, row)
	}
	if c.RxBytes > 0 || c.TxBytes > 0 {
		rows = append(rows, detailRow{label: l18n.Sprintf("Transfer"), value: l18n.Sprintf("%s received, %s sent", formatBytes(uint64(c.RxBytes)), formatBytes(uint64(c.TxBytes)))})
	}
	return rows
}

// card draws a titled panel of labelled values and returns its height.
func (s *scene) card(x, y, w float64, title string, rows []detailRow) float64 {
	const labelWidth, pad, rowGap = 128, 16, 8
	valueWidth := w - 2*pad - labelWidth
	heights := make([]float64, len(rows))
	height := float64(pad + 16 + 10)
	for i := range rows {
		heights[i] = s.wrappedHeight(rows[i].value, rows[i].font, valueWidth)
		if heights[i] < 20 {
			heights[i] = 20
		}
		height += heights[i] + rowGap
	}
	height += pad - rowGap

	s.fill(x, y, w, height, 8, theme.panel)
	s.label(title, fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 10
	for i, row := range rows {
		color := row.color
		if color == 0 {
			color = theme.text
		}
		if row.copyable {
			value := row.value
			s.button("copy:"+title+row.label, x+w-pad-132, y+pad-5, 132, 26, l18n.Sprintf("Copy public key"), buttonOutline, func() { walk.Clipboard().SetText(value) })
		}
		s.label(row.label, fontBody, theme.textDim, x+pad, rowY, labelWidth-8, 20, textLeft)
		s.text(row.value, row.font, color, x+pad+labelWidth, rowY+1, valueWidth, heights[i], textWrap)
		rowY += heights[i] + rowGap
	}
	return height
}

// buildHeader draws the bar on top of every screen but the main one.
func (s *scene) header(width float64, title string, back func()) {
	s.backButton(back)
	s.label(title, fontHeading, theme.text, 54, 0, width-54-16, headerHeight, textLeft)
	s.fill(0, headerHeight, width, 1, 0, theme.line)
}

// buildDetails draws the screen about one tunnel.
func (mtw *ManageTunnelsWindow) buildDetails(s *scene, width, height float64) {
	model := mtw.model
	name := mtw.detailsName
	back := func() { mtw.showScreen(screenStatus) }
	entry := model.entry(name)
	if entry == nil {
		s.header(width, name, back)
		return
	}
	look := lookFor(entry)
	left, inner := 24.0, width-48

	// The content, which scrolls between the header and the footer
	top, footerY := float64(headerHeight+1), height-footerHeight
	s.setClip(0, top, width, footerY-top)
	y := top + 18 - s.scroll
	if len(look.message) > 0 {
		y += s.notice(left, y, inner, look.messageKind, "", look.message) + 14
	}
	if title, text := connectionWarning(entry); len(text) > 0 {
		y += s.notice(left, y, inner, noticeAmber, title, text) + 14
	}
	samples := model.samples[name]
	if title, text := qualityWarning(entry, summarizeQuality(samples.seconds)); len(text) > 0 {
		y += s.notice(left, y, inner, noticeAmber, title, text) + 14
	}
	now := time.Now()
	if entry.state == manager.TunnelStarted && entry.config != nil {
		y += mtw.charts(s, left, y, inner, samples, now, 132, 112, true) + 14
	}
	if rows := connectionRows(entry, samples, now); len(rows) > 0 {
		y += s.card(left, y, inner, l18n.Sprintf("CONNECTION"), rows) + 14
	}
	if entry.state == manager.TunnelStarted && entry.pathLoaded {
		y += s.card(left, y, inner, l18n.Sprintf("PATH"), pathRows(&entry.path, model.diagnoses[name])) + 14
	}
	y += mtw.troubleshootingCard(s, left, y, inner, entry, now) + 14
	if IsAdmin && entry.settingsLoaded {
		y += mtw.tunnelSettings(s, left, y, inner, entry) + 14
	}
	if entry.config != nil {
		y += s.card(left, y, inner, l18n.Sprintf("INTERFACE"), interfaceRows(&entry.config.Interface)) + 14
		for i := range entry.config.Peers {
			connected := entry.state == manager.TunnelStarted && entry.health == manager.TunnelHealthConnected
			y += s.card(left, y, inner, l18n.Sprintf("PEER"), peerRows(&entry.config.Peers[i], connected)) + 14
		}
	}
	if height := mtw.historySection(s, left, y, inner, entry, now); height > 0 {
		y += height + 14
	}
	s.maxScroll = y + s.scroll + 4 - footerY
	s.clearClip()
	s.scrollThumb(width-10, top+4, footerY-top-8)

	// The header
	s.fill(0, 0, width, headerHeight, 0, theme.backdrop)
	s.header(width, name, back)
	s.label(look.short, fontBodyBold, look.shortColor, width/2, 0, width/2-20, headerHeight, textRight)

	// The footer
	s.fill(0, footerY, width, footerHeight, 0, theme.backdrop)
	s.fill(0, footerY, width, 1, 0, theme.line)
	style, label := look.primary, l18n.Sprintf("Deactivate")
	if !entry.active() {
		style, label = buttonGreen, l18n.Sprintf("Activate")
	}
	if !model.canToggle() {
		style = buttonDisabled
	}
	mainWidth := inner
	if IsAdmin {
		mainWidth = inner - 88 - 96 - 104
		s.button("edit", left+mainWidth+8, footerY+18, 80, 44, l18n.Sprintf("Edit"), buttonOutline, func() { model.editTunnel(mtw, name) })
		s.button("export-one", left+mainWidth+96, footerY+18, 88, 44, l18n.Sprintf("Export"), buttonOutline, func() { model.exportTunnel(mtw, name) })
		s.button("remove", left+mainWidth+192, footerY+18, 96, 44, l18n.Sprintf("Remove"), buttonDanger, func() {
			if model.deleteTunnel(mtw, name) {
				mtw.showScreen(screenStatus)
			}
		})
	}
	s.button("toggle", left, footerY+18, mainWidth, 44, label, style, func() { model.toggle(mtw, name) })
}

// tunnelColorName is how a color of manager.TunnelColors is called, or "None" for no color.
func tunnelColorName(name string) string {
	switch name {
	case "green":
		return l18n.Sprintf("Green")
	case "blue":
		return l18n.Sprintf("Blue")
	case "violet":
		return l18n.Sprintf("Violet")
	case "amber":
		return l18n.Sprintf("Amber")
	case "red":
		return l18n.Sprintf("Red")
	case "teal":
		return l18n.Sprintf("Teal")
	case "pink":
		return l18n.Sprintf("Pink")
	case "gray":
		return l18n.Sprintf("Gray")
	}
	return l18n.Sprintf("None")
}

const (
	swatchSize = 24
	swatchGap  = 8
)

// swatchRows is how many rows the color swatches take in a width.
func swatchRows(width float64) int {
	perRow := max(int((width+swatchGap)/(swatchSize+swatchGap)), 1)
	count := tunnelColorCount + 1
	return (count + perRow - 1) / perRow
}

// colorSwatches draws the choice of color of a tunnel, no color first, wrapping into rows, and returns its height.
func (mtw *ManageTunnelsWindow) colorSwatches(s *scene, x, y, w float64, entry *tunnelEntry) float64 {
	model, name := mtw.model, entry.tunnel.Name
	perRow := max(int((w+swatchGap)/(swatchSize+swatchGap)), 1)
	choices := append([]string{""}, manager.TunnelColors[:]...)
	for i, choice := range choices {
		choice := choice
		cellX := x + float64(i%perRow)*(swatchSize+swatchGap)
		cellY := y + float64(i/perRow)*(swatchSize+swatchGap)
		id := "color:" + choice
		if choice == "" {
			id = "color:none"
		}
		hover := s.hoverAmount(id, s.hit(id, cellX-3, cellY-3, swatchSize+6, swatchSize+6, func() { model.setColor(mtw, name, choice) }))
		if color, ok := tunnelColor(choice); ok {
			s.fill(cellX, cellY, swatchSize, swatchSize, swatchSize/2, color)
		} else {
			// No color: an empty circle, struck through.
			s.stroke(cellX+1, cellY+1, swatchSize-2, swatchSize-2, swatchSize/2-1, 1.5, theme.muted)
			s.line(1.5, theme.muted, cellX+6, cellY+swatchSize-6, cellX+swatchSize-6, cellY+6)
		}
		// The chosen color is ringed, and a ring fades in under the mouse.
		selected := 0.0
		if entry.settings.Color == choice {
			selected = 1
		}
		s.strokeFaded(cellX-4, cellY-4, swatchSize+8, swatchSize+8, swatchSize/2+4, 2, theme.text, s.animate("swatch:"+id, selected))
		s.strokeFaded(cellX-4, cellY-4, swatchSize+8, swatchSize+8, swatchSize/2+4, 1, theme.border, hover*(1-selected))
	}
	return float64(swatchRows(w))*(swatchSize+swatchGap) - swatchGap
}

// tunnelSettings draws the panel of the choices made for a tunnel: whether it is a favorite, its color, and
// whether its connection quality is measured, with what address. It returns its height.
func (mtw *ManageTunnelsWindow) tunnelSettings(s *scene, x, y, w float64, entry *tunnelEntry) float64 {
	const pad, labelWidth = 16, 128
	model, name := mtw.model, entry.tunnel.Name
	textWidth := w - 2*pad - toggleWidth - 16
	favoriteText := l18n.Sprintf("Favorites are listed first, here and in the tray menu.")
	favoriteHeight := s.wrappedHeight(favoriteText, fontSmall, textWidth)
	swatchWidth := w - 2*pad - labelWidth
	swatchesHeight := max(float64(swatchRows(swatchWidth))*(swatchSize+swatchGap)-swatchGap, 40)
	explanation := l18n.Sprintf("Pings an address through the tunnel once a second to show latency and loss. Off by default, as it sends traffic of its own.")
	if !entry.probingAllowed {
		explanation = l18n.Sprintf("Disabled by policy. Your administrator does not allow measuring connection quality.")
	}
	explanationHeight := s.wrappedHeight(explanation, fontSmall, textWidth)
	height := pad + 16 + 10 +
		22 + 4 + favoriteHeight + 16 +
		swatchesHeight + 16 + 1 + 16 +
		22 + 4 + explanationHeight + 12 + 30 + pad

	s.fill(x, y, w, height, 8, theme.panel)
	s.label(l18n.Sprintf("SETTINGS"), fontCaps, theme.textDim, x+pad, y+pad, w-2*pad, 16, textLeft)
	rowY := y + pad + 16 + 10

	s.label(l18n.Sprintf("Favorite"), fontBodyBold, theme.text, x+pad, rowY, textWidth, 22, textLeft)
	favorite := entry.settings.Favorite
	s.toggle("favorite", x+w-pad-toggleWidth, rowY-1, favorite, true, func() { model.setFavorite(mtw, name, !favorite) })
	rowY += 22 + 4
	s.text(favoriteText, fontSmall, theme.textDim, x+pad, rowY, textWidth, favoriteHeight, textWrap)
	rowY += favoriteHeight + 16

	// The name of the chosen color is written under the caption, so that it does not depend on telling colors apart.
	s.label(l18n.Sprintf("Color"), fontBody, theme.textDim, x+pad, rowY, labelWidth-8, 20, textLeft)
	s.label(tunnelColorName(entry.settings.Color), fontSmall, theme.text, x+pad, rowY+20, labelWidth-8, 18, textLeft)
	mtw.colorSwatches(s, x+pad+labelWidth, rowY+4, swatchWidth, entry)
	rowY += swatchesHeight + 16
	s.fill(x+pad, rowY, w-2*pad, 1, 0, theme.line)
	rowY += 1 + 16

	on := entry.settings.Probe && entry.probingAllowed
	s.label(l18n.Sprintf("Measure connection quality"), fontBodyBold, theme.text, x+pad, rowY, textWidth, 22, textLeft)
	want := !entry.settings.Probe
	s.toggle("probe", x+w-pad-toggleWidth, rowY-1, on, entry.probingAllowed, func() { model.setProbing(mtw, name, want) })
	rowY += 22 + 4
	explanationColor := theme.textDim
	if !entry.probingAllowed {
		explanationColor = theme.amberSoft
	}
	s.text(explanation, fontSmall, explanationColor, x+pad, rowY, textWidth, explanationHeight, textWrap)
	rowY += explanationHeight + 12

	target := entry.settings.ProbeTarget
	if len(target) == 0 {
		target = l18n.Sprintf("automatic")
	}
	const buttonWidth = 104
	s.label(l18n.Sprintf("Address"), fontBody, theme.textDim, x+pad, rowY, labelWidth-8, 30, textLeft)
	s.label(target, fontBody, theme.text, x+pad+labelWidth, rowY, w-2*pad-labelWidth-buttonWidth-8, 30, textLeft)
	style := buttonOutline
	if !entry.probingAllowed {
		style = buttonDisabled
	}
	s.button("probe-target", x+w-pad-buttonWidth, rowY, buttonWidth, 30, l18n.Sprintf("Change…"), style, func() { model.changeProbeTarget(mtw, name) })
	return height
}
