package models

import "time"

type TrafficInfo struct {
	Ingress uint64
	Egress  uint64
	IsNA    bool
}

type Service struct {
	Protocol      string
	Port          string
	BindAddr      string
	ProcessName   string
	PID           string
	ContainerName string
	InternalIP    string
	Status        string
	TrafficInfo   TrafficInfo
	Rule          string
	Chain         string
	Packets       uint64
	Bytes         uint64
	IsDocker      bool
}

type ScanResultMsg struct {
	Services  []Service
	PrevBytes map[string]uint64
	Time      time.Time
}

type ToastMsg struct{}
type TickMsg time.Time
