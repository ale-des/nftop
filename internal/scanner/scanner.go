package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nftop/internal/models"
)

type Scanner struct {
	prevBytes map[string]uint64
	lastScan  time.Time
}

func New() *Scanner {
	return &Scanner{
		prevBytes: make(map[string]uint64),
		lastScan:  time.Now(),
	}
}

func (s *Scanner) Scan() models.ScanResultMsg {
	now := time.Now()
	duration := now.Sub(s.lastScan).Seconds()
	if duration <= 0 {
		duration = 1
	}

	services := []models.Service{}
	newPrevBytes := make(map[string]uint64)

	// 1. Get ss output
	ssOut, _ := exec.Command("ss", "-tulpn", "-H").Output()
	lines := strings.Split(string(ssOut), "\n")

	// 2. Get Docker info gracefully (won't crash if missing)
	dockerIPs, dockerNames := getDockerInfo()

	// 3. Get nft ruleset
	nftOut, _ := exec.Command("nft", "-j", "list", "ruleset").Output()
	var ruleset map[string]interface{}
	json.Unmarshal(nftOut, &ruleset)

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		proto := fields[0]
		localAddr := fields[4]
		idx := strings.LastIndex(localAddr, ":")
		if idx == -1 {
			continue
		}
		ip := localAddr[:idx]
		if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
			ip = ip[1 : len(ip)-1]
		}
		port := localAddr[idx+1:]

		// Parse Process and PID
		processInfo := strings.Join(fields[6:], " ")
		procName, pid := extractProcess(processInfo)

		isDocker := (procName == "docker-proxy" || procName == "dockerd" || procName == "containerd")
		cName := dockerNames[port]
		intIP := dockerIPs[port]
		if cName != "" {
			isDocker = true
		}

		ruleStr, chain, pkts, ruleBytes, hasRule := matchRule(ruleset, port, intIP)
		status := determineStatus(ip, hasRule)

		// Traffic Calculation
		key := fmt.Sprintf("%s:%s", ip, port)
		var ingress uint64
		isNA := !hasRule || ruleBytes == 0

		if !isNA {
			prev := s.prevBytes[key]
			if ruleBytes >= prev {
				ingress = uint64(float64(ruleBytes-prev) / duration)
			}
			newPrevBytes[key] = ruleBytes
		}

		services = append(services, models.Service{
			Protocol:      proto,
			Port:          port,
			BindAddr:      ip,
			ProcessName:   procName,
			PID:           pid,
			ContainerName: cName,
			InternalIP:    intIP,
			Status:        status,
			TrafficInfo: models.TrafficInfo{
				Ingress: ingress,
				Egress:  0, // Merged to ingress due to single counter context in basic rules
				IsNA:    isNA,
			},
			Rule:     ruleStr,
			Chain:    chain,
			Packets:  pkts,
			Bytes:    ruleBytes,
			IsDocker: isDocker,
		})
	}

	s.prevBytes = newPrevBytes
	s.lastScan = now

	return models.ScanResultMsg{
		Services:  services,
		PrevBytes: newPrevBytes,
		Time:      now,
	}
}

func extractProcess(info string) (string, string) {
	nameRe := regexp.MustCompile(`"([^"]+)"`)
	pidRe := regexp.MustCompile(`pid=(\d+)`)
	name := "unknown"
	pid := "-"
	if m := nameRe.FindStringSubmatch(info); len(m) > 1 {
		name = m[1]
	}
	if m := pidRe.FindStringSubmatch(info); len(m) > 1 {
		pid = m[1]
	}
	return name, pid
}

func getDockerInfo() (map[string]string, map[string]string) {
	ips := make(map[string]string)
	names := make(map[string]string)

	psOut, err := exec.Command("docker", "ps", "-q").Output()
	if err != nil || len(psOut) == 0 {
		return ips, names
	}

	ids := strings.Fields(string(psOut))
	args := append([]string{"inspect"}, ids...)
	inspectOut, err := exec.Command("docker", args...).Output()
	if err != nil {
		return ips, names
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		return ips, names
	}

	for _, c := range containers {
		name := strings.TrimPrefix(c["Name"].(string), "/")
		netSettings, ok := c["NetworkSettings"].(map[string]interface{})
		if !ok {
			continue
		}
		var ip string
		if nets, ok := netSettings["Networks"].(map[string]interface{}); ok {
			for _, n := range nets {
				if netInfo, ok := n.(map[string]interface{}); ok {
					if ipVal, ok := netInfo["IPAddress"].(string); ok && ipVal != "" {
						ip = ipVal
						break
					}
				}
			}
		}

		if ports, ok := netSettings["Ports"].(map[string]interface{}); ok {
			for portProto, binds := range ports {
				if binds != nil {
					p := strings.Split(portProto, "/")[0]
					ips[p] = ip
					names[p] = name
				}
			}
		}
	}
	return ips, names
}

func matchRule(ruleset map[string]interface{}, port, ip string) (string, string, uint64, uint64, bool) {
	nftables, ok := ruleset["nftables"].([]interface{})
	if !ok {
		return "", "", 0, 0, false
	}

	for _, item := range nftables {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		rule, ok := itemMap["rule"].(map[string]interface{})
		if !ok {
			continue
		}

		ruleBytesJSON, _ := json.Marshal(rule)
		ruleStr := string(ruleBytesJSON)

		// Basic matching for the port or internal IP in the JSON rule representation
		if strings.Contains(ruleStr, fmt.Sprintf(":%s", port)) || (ip != "" && strings.Contains(ruleStr, ip)) || strings.Contains(ruleStr, port) {
			chain, _ := rule["chain"].(string)
			var pkts, bts uint64
			pktRe := regexp.MustCompile(`"packets":\s*(\d+)`)
			bytesRe := regexp.MustCompile(`"bytes":\s*(\d+)`)
			if m := pktRe.FindStringSubmatch(ruleStr); len(m) > 1 {
				pkts, _ = strconv.ParseUint(m[1], 10, 64)
			}
			if m := bytesRe.FindStringSubmatch(ruleStr); len(m) > 1 {
				bts, _ = strconv.ParseUint(m[1], 10, 64)
			}
			// Constructing a simplified representation since parsing arbitrary nft expr is complex
			exprRep := fmt.Sprintf("ip daddr * tcp dport %s accept", port)
			if ip != "" {
				exprRep = fmt.Sprintf("ip daddr %s tcp dport %s accept", ip, port)
			}
			handle := "unknown"
			if h, ok := rule["handle"].(float64); ok {
				handle = fmt.Sprintf("#%.0f", h)
			}
			chainMeta := fmt.Sprintf("%s (Handle: %s)", chain, handle)
			return exprRep, chainMeta, pkts, bts, true
		}
	}
	return "", "", 0, 0, false
}

func determineStatus(bindAddr string, hasRule bool) string {
	if bindAddr == "127.0.0.1" || bindAddr == "::1" || strings.HasPrefix(bindAddr, "172.") || strings.HasPrefix(bindAddr, "10.") || strings.HasPrefix(bindAddr, "192.168.") {
		return "SAFE"
	}
	if bindAddr == "0.0.0.0" || bindAddr == "::" || bindAddr == "*" {
		if hasRule {
			return "ALLOWED"
		}
		return "EXPOSED"
	}
	return "SAFE"
}