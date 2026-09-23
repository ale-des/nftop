package ui

import (
	"time"

	"nftop/internal/models"
	"nftop/internal/scanner"
)

type ViewMode int
type SortMode int
type Panel int

const (
	ModeDetailed ViewMode = iota
	ModeCompact
)

const (
	SortTraffic SortMode = iota
	SortName
	SortPort
)

const (
	PanelList Panel = iota
	PanelInspector
)

var intervals = []time.Duration{
	time.Second,
	2 * time.Second,
	5 * time.Second,
	15 * time.Second,
	30 * time.Second,
	time.Minute,
}

type Model struct {
	isRoot   bool
	width    int
	height   int
	services []models.Service
	filtered []models.Service
	scanner  *scanner.Scanner

	listOffset      int
	inspectorOffset int
	helpOffset      int
	selectedIndex   int

	activePanel Panel
	viewMode    ViewMode
	sortMode    SortMode

	searchQuery  string
	searchActive bool
	dockerOnly   bool
	exposedOnly  bool

	tickIndex int
	showHelp  bool
	showToast bool
}

func NewModel(isRoot bool) *Model {
	return &Model{
		isRoot:      isRoot,
		scanner:     scanner.New(),
		activePanel: PanelList,
		viewMode:    ModeDetailed,
		sortMode:    SortTraffic,
		tickIndex:   0,
	}
}
