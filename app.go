package main

import (
	"context"

	"github.com/google/gopacket/pcap"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// / Cleanup all go routines
func (a *App) shutdown(context.Context) {
	cleanUp <- true
}

func (b *App) beforeClose(ctx context.Context) (prevent bool) {
	dialog, err := runtime.MessageDialog(ctx, runtime.MessageDialogOptions{
		Type:    runtime.QuestionDialog,
		Title:   "Quit?",
		Message: "Are you sure you want to exit?",
	})

	if err != nil {
		return false
	}
	return dialog != "Yes"
}

func (a *App) FindInterfaces() []pcap.Interface {
	interfaces, err := FindDevices()
	if err != nil {
		return []pcap.Interface{}
	}
	return interfaces
}

func (a *App) GetPackets(name string) {
	// cancelScan <- true
	go ScanDevice(name, "tcp", a.ctx)
}

func (a *App) PauseScan() {
	cancelScan <- true
}

func (a *App) EnableCapture() {
	cancelScan <- true
}
