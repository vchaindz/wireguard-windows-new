/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
)

// A tunnelEntry is what the UI knows about one tunnel.
type tunnelEntry struct {
	tunnel            manager.Tunnel
	state             manager.TunnelState
	health            manager.TunnelHealth
	conflictSuspected bool
	unstable          bool
	// config is the runtime configuration of a started tunnel, or the stored one of the tunnel whose details are shown.
	config *conf.Config
	// metrics is what the manager has observed about the tunnel since the manager started.
	metrics manager.TunnelMetrics
	// settings are loaded for every tunnel on full reloads, as the lists show their colors and favorites.
	settings       manager.TunnelSettings
	probingAllowed bool
	settingsLoaded bool
	// history is loaded for the tunnel whose details are shown only, as the other screens do not show it.
	// historyEnabled is false when policy disables connection history.
	history        manager.TunnelHistory
	historyEnabled bool
	historyLoaded  bool
	// path is how the tunnel whose details are shown reaches its peers, loaded while it is started.
	path       manager.TunnelPath
	pathLoaded bool
}

func (entry *tunnelEntry) active() bool {
	return entry.state == manager.TunnelStarted || entry.state == manager.TunnelStarting || entry.state == manager.TunnelStopping
}

// The appModel holds the tunnels as the manager reports them and performs the actions on them. Its
// fields are read and written on the UI thread only; a single worker goroutine talks to the manager.
type appModel struct {
	entries         []tunnelEntry
	globalState     manager.TunnelState
	updateAvailable bool
	// lastUsed is the tunnel that was most recently toggled, offered for activation when none is active.
	lastUsed string
	// samples holds what the manager sampled of the started tunnels, by name.
	samples map[string]tunnelSamples
	// wantMinutes is set while a screen shows a range that needs the per-minute samples. The worker reads it.
	wantMinutes int32
	// diagnoses holds the latest test of each tunnel that was tested since the window opened, by name.
	diagnoses map[string]*tunnelDiagnosis

	// The manager is told whether the window is watching from a goroutine, as the call may have to wait for
	// the worker; watchWanted is what it should be told and watchSent what it was told last.
	watchLock   sync.Mutex
	watchSend   sync.Mutex
	watchWanted bool
	watchSent   bool

	synchronize func(func())
	changed     []func()

	refreshRequests chan struct{}
	// fullRefreshPending is set when the next refresh has to reload everything, not only the counters.
	fullRefreshPending int32
	detailsLock        sync.Mutex
	detailsName        string

	tunnelChangedCB  *manager.TunnelChangeCallback
	tunnelHealthCB   *manager.TunnelHealthCallback
	tunnelsChangedCB *manager.TunnelsChangeCallback
	disposeOnce      sync.Once
}

func newAppModel(synchronize func(func())) *appModel {
	model := &appModel{
		synchronize:     synchronize,
		refreshRequests: make(chan struct{}, 1),
	}
	go func() {
		// The tunnels that the last full load found started; only these have counters and samples worth updating.
		var started []manager.Tunnel
		stores := make(map[string]*sampleStore)
		// The history of the tunnel whose details are shown changes only while it is active, and the manager
		// writes it once a minute, so it is fetched again at about that rate.
		var historyName string
		var historyFetched time.Time
		// The path changes when the computer changes networks, which a person may do while looking at it, and
		// reading it costs only a look at the routing tables, so it is fetched more often.
		var pathName string
		var pathFetched time.Time
		for range model.refreshRequests {
			full := atomic.SwapInt32(&model.fullRefreshPending, 0) != 0
			var (
				entries     []tunnelEntry
				globalState manager.TunnelState
			)
			if full {
				entries, globalState = model.load()
				started = started[:0]
				historyName, pathName = "", ""
				for i := range entries {
					if entries[i].state == manager.TunnelStarted {
						started = append(started, entries[i].tunnel)
					}
					if entries[i].historyLoaded {
						historyName, historyFetched = entries[i].tunnel.Name, time.Now()
					}
					if entries[i].pathLoaded {
						pathName, pathFetched = entries[i].tunnel.Name, time.Now()
					}
				}
			} else if len(started) == 0 {
				continue
			}
			type historyUpdate struct {
				history manager.TunnelHistory
				enabled bool
			}
			var freshHistory *historyUpdate
			if !full && len(historyName) > 0 && time.Since(historyFetched) >= historyRefreshInterval {
				historyFetched = time.Now()
				for _, tunnel := range started {
					if tunnel.Name != historyName {
						continue
					}
					if history, enabled, err := tunnel.History(); err == nil {
						freshHistory = &historyUpdate{history, enabled}
					}
				}
			}
			var freshPath *manager.TunnelPath
			if !full && len(pathName) > 0 && time.Since(pathFetched) >= pathRefreshInterval {
				pathFetched = time.Now()
				for _, tunnel := range started {
					if tunnel.Name != pathName {
						continue
					}
					if path, err := tunnel.Path(); err == nil {
						freshPath = &path
					}
				}
			}
			type counters struct {
				config  *conf.Config
				metrics manager.TunnelMetrics
			}
			var fresh map[string]counters
			if !full {
				fresh = make(map[string]counters, len(started))
				for _, tunnel := range started {
					if config, err := tunnel.RuntimeConfig(); err == nil {
						metrics, _ := tunnel.Metrics()
						fresh[tunnel.Name] = counters{&config, metrics}
					}
				}
			}
			samples := fetchSamples(started, stores, atomic.LoadInt32(&model.wantMinutes) != 0, time.Now())
			model.synchronize(func() {
				if full {
					model.entries, model.globalState = entries, globalState
				} else {
					for i := range model.entries {
						entry := &model.entries[i]
						if update, ok := fresh[entry.tunnel.Name]; ok && entry.state == manager.TunnelStarted {
							entry.config, entry.metrics = update.config, update.metrics
						}
						if freshHistory != nil && entry.tunnel.Name == historyName && entry.historyLoaded {
							entry.history, entry.historyEnabled = freshHistory.history, freshHistory.enabled
						}
						if freshPath != nil && entry.tunnel.Name == pathName && entry.pathLoaded {
							entry.path = *freshPath
						}
					}
				}
				model.samples = samples
				model.notifyChanged()
			})
		}
	}()
	// What a notification says is shown at once; a state change is followed by a full reload, which also
	// picks up the runtime configuration of a tunnel that has just started.
	model.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(func(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
		name := tunnel.Name
		model.synchronize(func() {
			model.globalState = globalState
			if entry := model.entry(name); entry != nil && entry.state != state {
				entry.state = state
				if state != manager.TunnelStarted {
					entry.health, entry.conflictSuspected, entry.unstable = manager.TunnelHealthUnknown, false, false
				}
			}
			model.notifyChanged()
		})
		model.refresh()
	})
	model.tunnelHealthCB = manager.IPCClientRegisterTunnelHealth(func(tunnel *manager.Tunnel, health manager.TunnelHealth, conflictSuspected, unstable bool) {
		name := tunnel.Name
		model.synchronize(func() {
			if entry := model.entry(name); entry != nil && entry.state == manager.TunnelStarted {
				entry.health, entry.conflictSuspected, entry.unstable = health, conflictSuspected, unstable
				model.notifyChanged()
			}
		})
	})
	model.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(model.refresh)
	model.refresh()
	return model
}

// dispose may be called more than once: destroying the window disposes of it a second time.
func (model *appModel) dispose() {
	model.disposeOnce.Do(func() {
		model.tunnelChangedCB.Unregister()
		model.tunnelHealthCB.Unregister()
		model.tunnelsChangedCB.Unregister()
		close(model.refreshRequests)
	})
}

// onChanged registers a function that is called on the UI thread whenever the tunnels were reloaded.
func (model *appModel) onChanged(changed func()) {
	model.changed = append(model.changed, changed)
}

// A sampleStore is what the worker keeps of the samples of one started tunnel.
type sampleStore struct {
	tunnelSamples
	minutesFetched time.Time
}

// fetchSamples brings the stores of the started tunnels up to date with the manager and returns what the UI
// thread is to see. Only samples newer than those held are asked for, so that every refresh transfers little.
// The per-minute samples are fetched only if wanted and then at most every minuteSampleRefresh.
func fetchSamples(started []manager.Tunnel, stores map[string]*sampleStore, wantMinutes bool, now time.Time) map[string]tunnelSamples {
	result := make(map[string]tunnelSamples, len(started))
	for _, tunnel := range started {
		store := stores[tunnel.Name]
		if store == nil {
			store = new(sampleStore)
			stores[tunnel.Name] = store
		}
		var since time.Time
		if n := len(store.seconds); n > 0 {
			since = store.seconds[n-1].Time
		}
		if newer, err := tunnel.Samples(manager.SampleResolutionSecond, since); err == nil {
			store.seconds = appendSamples(store.seconds, newer, secondSampleCapacity)
		}
		switch {
		case !wantMinutes:
			store.minutes, store.minutesFetched = nil, time.Time{}
		case now.Sub(store.minutesFetched) >= minuteSampleRefresh || now.Before(store.minutesFetched):
			since = time.Time{}
			if n := len(store.minutes); n > 0 {
				since = store.minutes[n-1].Time
			}
			if newer, err := tunnel.Samples(manager.SampleResolutionMinute, since); err == nil {
				store.minutes = appendSamples(store.minutes, newer, minuteSampleCapacity)
				store.minutesFetched = now
			}
		}
		result[tunnel.Name] = store.tunnelSamples
	}
	for name := range stores {
		if _, ok := result[name]; !ok {
			delete(stores, name)
		}
	}
	return result
}

// useMinuteSamples tells the worker whether a screen shows a range that needs the per-minute samples.
func (model *appModel) useMinuteSamples(use bool) {
	value := int32(0)
	if use {
		value = 1
	}
	if atomic.SwapInt32(&model.wantMinutes, value) != value && use {
		model.refreshCounters()
	}
}

// watch tells the manager whether the window is shown, so that it samples every second while it is. The
// call is made from a goroutine; whichever runs last sends what was wanted last.
func (model *appModel) watch(watching bool) {
	model.watchLock.Lock()
	model.watchWanted = watching
	model.watchLock.Unlock()
	go func() {
		model.watchSend.Lock()
		defer model.watchSend.Unlock()
		model.watchLock.Lock()
		wanted := model.watchWanted
		model.watchLock.Unlock()
		if wanted != model.watchSent && manager.IPCClientWatch(wanted) == nil {
			model.watchSent = wanted
		}
	}()
}

func (model *appModel) notifyChanged() {
	for _, changed := range model.changed {
		changed()
	}
}

// refresh asks the worker to reload the tunnels. It never blocks and may be called from any goroutine.
func (model *appModel) refresh() {
	atomic.StoreInt32(&model.fullRefreshPending, 1)
	model.refreshCounters()
}

// refreshCounters asks the worker to reload only what changes while a tunnel runs: the handshake times,
// traffic counters and samples of the started tunnels.
func (model *appModel) refreshCounters() {
	defer func() { recover() }() // The model may have been disposed of meanwhile.
	select {
	case model.refreshRequests <- struct{}{}:
	default:
	}
}

// showDetailsOf makes the model also load the stored configuration of a tunnel that is not active.
func (model *appModel) showDetailsOf(name string) {
	model.detailsLock.Lock()
	model.detailsName = name
	model.detailsLock.Unlock()
	model.refresh()
}

func (model *appModel) load() (entries []tunnelEntry, globalState manager.TunnelState) {
	model.detailsLock.Lock()
	detailsName := model.detailsName
	model.detailsLock.Unlock()

	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return nil, manager.TunnelUnknown
	}
	entries = make([]tunnelEntry, 0, len(tunnels))
	for _, tunnel := range tunnels {
		entry := tunnelEntry{tunnel: tunnel}
		if entry.state, err = tunnel.State(); err != nil {
			entry.state = manager.TunnelUnknown
		}
		entry.metrics, _ = tunnel.Metrics()
		if entry.state == manager.TunnelStarted {
			entry.health, entry.conflictSuspected, entry.unstable, _ = tunnel.Health()
			if config, err := tunnel.RuntimeConfig(); err == nil {
				entry.config = &config
			}
		}
		if entry.config == nil && tunnel.Name == detailsName {
			if config, err := tunnel.StoredConfig(); err == nil {
				entry.config = &config
			}
		}
		if tunnel.Name == detailsName && entry.state == manager.TunnelStarted {
			if path, err := tunnel.Path(); err == nil {
				entry.path, entry.pathLoaded = path, true
			}
		}
		if tunnel.Name == detailsName {
			if history, enabled, err := tunnel.History(); err == nil {
				entry.history, entry.historyEnabled, entry.historyLoaded = history, enabled, true
			}
		}
		// Settings change rarely and only through this UI, which reloads in full after changing them, so they are
		// not part of the frequent counter updates.
		if settings, allowed, err := tunnel.Settings(); err == nil {
			entry.settings, entry.probingAllowed, entry.settingsLoaded = settings, allowed, true
		}
		entries = append(entries, entry)
	}
	sortEntries(entries)
	if globalState, err = manager.IPCClientGlobalState(); err != nil {
		globalState = manager.TunnelUnknown
	}
	return entries, globalState
}

// sortEntries puts favorites first and sorts by name within favorites and the rest.
func sortEntries(entries []tunnelEntry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].settings.Favorite != entries[j].settings.Favorite {
			return entries[i].settings.Favorite
		}
		return conf.TunnelNameIsLess(entries[i].tunnel.Name, entries[j].tunnel.Name)
	})
}

func (model *appModel) entry(name string) *tunnelEntry {
	for i := range model.entries {
		if model.entries[i].tunnel.Name == name {
			return &model.entries[i]
		}
	}
	return nil
}

// severity ranks how much a started tunnel needs attention.
func (entry *tunnelEntry) severity() int {
	switch {
	case entry.health == manager.TunnelHealthNoConnectionNetworkBlocked:
		return 5
	case entry.health == manager.TunnelHealthNoConnection:
		return 4
	case entry.health == manager.TunnelHealthWaitingForPeer:
		return 3
	case entry.conflictSuspected || entry.unstable:
		return 2
	case entry.health == manager.TunnelHealthConnected:
		return 1
	}
	return 0
}

// hero is the tunnel that the status screen is about: of the started ones the one that needs attention
// most, and the first by name among equals; failing that, one that is starting or stopping.
func (model *appModel) hero() *tunnelEntry {
	var hero *tunnelEntry
	for i := range model.entries {
		entry := &model.entries[i]
		if entry.state == manager.TunnelStarted && (hero == nil || entry.severity() > hero.severity()) {
			hero = entry
		}
	}
	if hero != nil {
		return hero
	}
	for i := range model.entries {
		if model.entries[i].active() {
			return &model.entries[i]
		}
	}
	return nil
}

// suggested is the tunnel offered for activation when none is active.
func (model *appModel) suggested() *tunnelEntry {
	if entry := model.entry(model.lastUsed); entry != nil {
		return entry
	}
	if len(model.entries) > 0 {
		return &model.entries[0]
	}
	return nil
}

func (model *appModel) canToggle() bool {
	return model.globalState == manager.TunnelStarted || model.globalState == manager.TunnelStopped
}

// Actions. They are called on the UI thread; owner is the window that dialogs belong to.

func (model *appModel) toggle(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil || !model.canToggle() {
		return
	}
	model.lastUsed = name
	tunnel := entry.tunnel
	go func() {
		oldState, err := tunnel.Toggle()
		if err == nil {
			return
		}
		model.synchronize(func() {
			switch oldState {
			case manager.TunnelUnknown:
				showErrorCustom(owner, l18n.Sprintf("Failed to determine tunnel state"), err.Error())
			case manager.TunnelStopped:
				showErrorCustom(owner, l18n.Sprintf("Failed to activate tunnel"), err.Error())
			case manager.TunnelStarted:
				showErrorCustom(owner, l18n.Sprintf("Failed to deactivate tunnel"), err.Error())
			}
		})
	}()
}

// changeSettings changes a setting of a tunnel. What is shown changes at once and changes back, with an error
// titled failure, if the manager refuses.
func (model *appModel) changeSettings(owner walk.Form, name string, change func(*manager.TunnelSettings), failure string) {
	entry := model.entry(name)
	if entry == nil || !entry.settingsLoaded {
		return
	}
	previous := entry.settings
	settings := previous
	change(&settings)
	if settings == previous {
		return
	}
	// Sorting moves the entries, so the tunnel is taken before.
	tunnel := entry.tunnel
	entry.settings = settings
	sortEntries(model.entries)
	model.notifyChanged()
	go func() {
		err := tunnel.SetSettings(settings)
		model.synchronize(func() {
			if err != nil {
				if entry := model.entry(name); entry != nil && entry.settings == settings {
					entry.settings = previous
					sortEntries(model.entries)
					model.notifyChanged()
				}
				showErrorCustom(owner, failure, err.Error())
				return
			}
			model.refresh()
		})
	}()
}

// setProbing switches measuring the connection quality of a tunnel on or off.
func (model *appModel) setProbing(owner walk.Form, name string, probe bool) {
	model.changeSettings(owner, name, func(settings *manager.TunnelSettings) { settings.Probe = probe }, l18n.Sprintf("Unable to change the measurement"))
}

// setFavorite makes a tunnel a favorite, which lists it first, or an ordinary tunnel again.
func (model *appModel) setFavorite(owner walk.Form, name string, favorite bool) {
	model.changeSettings(owner, name, func(settings *manager.TunnelSettings) { settings.Favorite = favorite }, l18n.Sprintf("Unable to change the favorite"))
}

// setColor marks a tunnel with one of manager.TunnelColors, or with none if the name is empty.
func (model *appModel) setColor(owner walk.Form, name, color string) {
	model.changeSettings(owner, name, func(settings *manager.TunnelSettings) { settings.Color = color }, l18n.Sprintf("Unable to change the color"))
}

// changeProbeTarget asks for the address that the connection quality of a tunnel is measured with.
func (model *appModel) changeProbeTarget(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil || !entry.settingsLoaded {
		return
	}
	tunnel := entry.tunnel
	settings := entry.settings
	if runProbeTargetDialog(owner, settings.ProbeTarget, func(target string) error {
		changed := settings
		changed.ProbeTarget = target
		if err := tunnel.SetSettings(changed); err != nil {
			return err
		}
		settings = changed
		return nil
	}) {
		// The manager stores the address in its own spelling, which the next load shows.
		if entry := model.entry(name); entry != nil {
			entry.settings.ProbeTarget = settings.ProbeTarget
			model.notifyChanged()
		}
		model.refresh()
	}
}

func (model *appModel) addTunnel(owner walk.Form) {
	if config := runEditDialog(owner, nil); config != nil {
		if _, err := manager.IPCClientNewTunnel(config); err != nil {
			showErrorCustom(owner, l18n.Sprintf("Unable to create tunnel"), err.Error())
		}
	}
}

func (model *appModel) editTunnel(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil {
		return
	}
	tunnel := entry.tunnel
	if config := runEditDialog(owner, &tunnel); config != nil {
		model.showDetailsOf(config.Name)
		go func() {
			priorState, err := tunnel.State()
			tunnel.Delete()
			tunnel.WaitForStop()
			tunnel, err2 := manager.IPCClientNewTunnel(config)
			if err == nil && err2 == nil && (priorState == manager.TunnelStarting || priorState == manager.TunnelStarted) {
				tunnel.Start()
			}
		}()
	}
}

// deleteTunnel asks for confirmation and removes a tunnel. It reports whether the user confirmed.
func (model *appModel) deleteTunnel(owner walk.Form, name string) bool {
	entry := model.entry(name)
	if entry == nil {
		return false
	}
	question := l18n.Sprintf("Are you sure you would like to delete tunnel ‘%s’?", name)
	if walk.DlgCmdNo == walk.MsgBox(owner, l18n.Sprintf("Delete tunnel ‘%s’", name), l18n.Sprintf("%s You cannot undo this action.", question), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return false
	}
	tunnel := entry.tunnel
	go func() {
		if err := tunnel.Delete(); err != nil {
			model.synchronize(func() {
				showErrorCustom(owner, l18n.Sprintf("Unable to delete tunnel"), l18n.Sprintf("A tunnel was unable to be removed: %s", err.Error()))
			})
		}
	}()
	return true
}

// clearHistory asks for confirmation and deletes the connection history of a tunnel.
func (model *appModel) clearHistory(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil {
		return
	}
	question := l18n.Sprintf("Are you sure you would like to clear the connection history of tunnel ‘%s’?", name)
	if walk.DlgCmdNo == walk.MsgBox(owner, l18n.Sprintf("Clear history of ‘%s’", name), l18n.Sprintf("%s You cannot undo this action.", question), walk.MsgBoxYesNo|walk.MsgBoxIconWarning) {
		return
	}
	tunnel := entry.tunnel
	go func() {
		err := tunnel.ClearHistory()
		model.synchronize(func() {
			if err != nil {
				showErrorCustom(owner, l18n.Sprintf("Unable to clear history"), err.Error())
				return
			}
			model.refresh()
		})
	}()
}

// saveHistory writes the sessions and the usage per day of a tunnel to a CSV file that the user chooses. The
// history is read again first, so that the file has the latest minute too.
func (model *appModel) saveHistory(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil {
		return
	}
	tunnel := entry.tunnel
	dlg := walk.FileDialog{
		Filter:   l18n.Sprintf("CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"),
		FilePath: fmt.Sprintf("wireguard-history-%s-%s.csv", name, time.Now().Format("2006-01-02")),
		Title:    l18n.Sprintf("Save connection history to file"),
	}
	if ok, _ := dlg.ShowSave(owner); !ok {
		return
	}
	if dlg.FilterIndex == 1 && !strings.HasSuffix(strings.ToLower(dlg.FilePath), ".csv") {
		dlg.FilePath += ".csv"
	}
	history, enabled, err := tunnel.History()
	if err == nil && !enabled {
		err = errors.New(l18n.Sprintf("Connection history is disabled by policy."))
	}
	if err != nil {
		showErrorCustom(owner, l18n.Sprintf("Unable to read connection history"), err.Error())
		return
	}
	writeFileWithOverwriteHandling(owner, dlg.FilePath, func(file *os.File) error {
		return writeHistoryCSV(file, history)
	})
}

func (model *appModel) importTunnels(owner walk.Form) {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration Files (*.zip, *.conf)|*.zip;*.conf|All Files (*.*)|*.*"),
		Title:  l18n.Sprintf("Import tunnel(s) from file"),
	}
	if ok, _ := dlg.ShowOpenMultiple(owner); !ok {
		return
	}
	model.importFiles(owner, dlg.FilePaths)
}

func (model *appModel) importFiles(owner walk.Form, paths []string) {
	go func() {
		syncedMsgBox := func(title, message string, flags walk.MsgBoxStyle) {
			model.synchronize(func() {
				walk.MsgBox(owner, title, message, flags)
			})
		}
		type unparsedConfig struct {
			Name   string
			Config string
		}

		var (
			unparsedConfigs []unparsedConfig
			lastErr         error
		)

		for _, path := range paths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".conf":
				textConfig, err := os.ReadFile(path)
				if err != nil {
					lastErr = err
					continue
				}
				unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), Config: string(textConfig)})
			case ".zip":
				// 1 .conf + 1 error .zip edge case?
				r, err := zip.OpenReader(path)
				if err != nil {
					lastErr = err
					continue
				}

				for _, f := range r.File {
					if strings.ToLower(filepath.Ext(f.Name)) != ".conf" {
						continue
					}

					rc, err := f.Open()
					if err != nil {
						lastErr = err
						continue
					}
					textConfig, err := io.ReadAll(rc)
					rc.Close()
					if err != nil {
						lastErr = err
						continue
					}
					unparsedConfigs = append(unparsedConfigs, unparsedConfig{Name: strings.TrimSuffix(filepath.Base(f.Name), filepath.Ext(f.Name)), Config: string(textConfig)})
				}

				r.Close()
			}
		}

		if lastErr != nil || unparsedConfigs == nil {
			if lastErr == nil {
				lastErr = errors.New(l18n.Sprintf("no configuration files were found"))
			}
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not import selected configuration: %v", lastErr), walk.MsgBoxIconWarning)
			return
		}

		existingTunnelList, err := manager.IPCClientTunnels()
		if err != nil {
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Could not enumerate existing tunnels: %v", err), walk.MsgBoxIconWarning)
			return
		}
		existingLowerTunnels := make(map[string]bool, len(existingTunnelList))
		for _, tunnel := range existingTunnelList {
			existingLowerTunnels[strings.ToLower(tunnel.Name)] = true
		}

		configCount := 0
		for _, unparsedConfig := range unparsedConfigs {
			if existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] {
				lastErr = errors.New(l18n.Sprintf("Another tunnel already exists with the name ‘%s’", unparsedConfig.Name))
				continue
			}
			config, err := conf.FromWgQuickWithUnknownEncoding(unparsedConfig.Config, unparsedConfig.Name)
			if err != nil {
				lastErr = err
				continue
			}
			_, err = manager.IPCClientNewTunnel(config)
			if err != nil {
				lastErr = err
				continue
			}
			existingLowerTunnels[strings.ToLower(unparsedConfig.Name)] = true
			configCount++
		}

		m, n := configCount, len(unparsedConfigs)
		switch {
		case n == 1 && m != n:
			syncedMsgBox(l18n.Sprintf("Error"), l18n.Sprintf("Unable to import configuration: %v", lastErr), walk.MsgBoxIconWarning)
		case n == 1 && m == n:
			// nothing
		case m == n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d tunnels", m), walk.MsgBoxIconInformation)
		case m != n:
			syncedMsgBox(l18n.Sprintf("Imported tunnels"), l18n.Sprintf("Imported %d of %d tunnels", m, n), walk.MsgBoxIconWarning)
		}
	}()
}

// exportTunnel saves the configuration of one tunnel as a .conf file, which holds its private key like the zip of
// all tunnels does.
func (model *appModel) exportTunnel(owner walk.Form, name string) {
	entry := model.entry(name)
	if entry == nil {
		return
	}
	dlg := walk.FileDialog{
		Filter:   l18n.Sprintf("Configuration Files (*.conf)|*.conf"),
		FilePath: name + ".conf",
		Title:    l18n.Sprintf("Export tunnel ‘%s’", name),
	}
	if ok, _ := dlg.ShowSave(owner); !ok {
		return
	}
	if !strings.HasSuffix(strings.ToLower(dlg.FilePath), ".conf") {
		dlg.FilePath += ".conf"
	}

	tunnel := entry.tunnel
	writeFileWithOverwriteHandling(owner, dlg.FilePath, func(file *os.File) error {
		cfg, err := tunnel.StoredConfig()
		if err != nil {
			return fmt.Errorf("exportTunnel: tunnel.StoredConfig failed: %w", err)
		}
		if _, err := file.WriteString(cfg.ToWgQuick()); err != nil {
			return fmt.Errorf("exportTunnel: writing the configuration failed: %w", err)
		}
		return nil
	})
}

func (model *appModel) exportTunnels(owner walk.Form) {
	dlg := walk.FileDialog{
		Filter: l18n.Sprintf("Configuration ZIP Files (*.zip)|*.zip"),
		Title:  l18n.Sprintf("Export tunnels to zip"),
	}
	if ok, _ := dlg.ShowSave(owner); !ok {
		return
	}
	if !strings.HasSuffix(dlg.FilePath, ".zip") {
		dlg.FilePath += ".zip"
	}

	tunnels := make([]manager.Tunnel, len(model.entries))
	for i := range model.entries {
		tunnels[i] = model.entries[i].tunnel
	}
	writeFileWithOverwriteHandling(owner, dlg.FilePath, func(file *os.File) error {
		writer := zip.NewWriter(file)

		for _, tunnel := range tunnels {
			cfg, err := tunnel.StoredConfig()
			if err != nil {
				return fmt.Errorf("onExportTunnels: tunnel.StoredConfig failed: %w", err)
			}

			w, err := writer.Create(tunnel.Name + ".conf")
			if err != nil {
				return fmt.Errorf("onExportTunnels: writer.Create failed: %w", err)
			}

			if _, err := w.Write(([]byte)(cfg.ToWgQuick())); err != nil {
				return fmt.Errorf("onExportTunnels: cfg.ToWgQuick failed: %w", err)
			}
		}

		return writer.Close()
	})
}
