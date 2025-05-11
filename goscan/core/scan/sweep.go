package scan

import (
	"fmt"
	"net"
	"github.com/marco-lancini/goscan/core/model"
	"github.com/marco-lancini/goscan/core/utils"
)

// ---------------------------------------------------------------------------------------
// DISPATCHER
// ---------------------------------------------------------------------------------------
func ScanSweep(kind string, target string) {
	// Dispatch scan
	switch kind {
	case "PING":
		utils.Config.Log.LogInfo("Starting Ping Sweep")
		folder, file, nmapArgs := "sweep", "ping", utils.Const_NMAP_SWEEP
		execSweep(file, target, folder, file, nmapArgs)

	case "ARP":
		utils.Config.Log.LogInfo("Starting ARP Sweep")
		folder, file := "sweep", "arp"
		execARPSweep(file, target, folder, file)

	default:
		utils.Config.Log.LogError("Invalid type of scan")
		return
	}
}

func execSweep(name, target, folder, file, nmapArgs string) {
	targets := model.GetAllTargets(utils.Config.DB)
	for _, h := range targets {
		// Scan only if:
		//   - target is ALL
		//   - or if target is TO_ANALYZE and host still need to be analyzed
		//   - or if host is the selected one
		if target == "ALL" || 
		   (target == "TO_ANALYZE" && h.Step == model.IMPORTED.String()) || 
		   target == h.Address {
			temp := h
			fname := fmt.Sprintf("%s_%s", file, h.Address)
			go workerSweep(name, &temp, folder, fname, nmapArgs)
		}
	}
}

func execARPSweep(name, target, folder, file string) {
	targets := model.GetAllTargets(utils.Config.DB)
	for _, h := range targets {
		if target == "ALL" || 
		   (target == "TO_ANALYZE" && h.Step == model.IMPORTED.String()) || 
		   target == h.Address {
			temp := h
			fname := fmt.Sprintf("%s_%s", file, h.Address)
			go workerARPSweep(name, &temp, folder, fname)
		}
	}
}

// ---------------------------------------------------------------------------------------
// WORKER
// ---------------------------------------------------------------------------------------
func workerSweep(name string, h *model.Target, folder string, file string, nmapArgs string) {
	// Instantiate new NmapScan
	s := NewScan(name, h.Address, folder, file, nmapArgs)
	ScansList = append(ScansList, s)

	// Run the scan
	s.RunNmap()

	// Parse nmap's output
	res := s.ParseOutput()
	if res != nil {
		// Identify live hosts
		for _, host := range res.Hosts {
			status := host.Status.State
			if status == "up" {
				// Save as host
				addr := host.Addresses[0].Addr
				model.AddHost(utils.Config.DB, addr, "up", model.NEW.String())
			}
		}
	}

	// Update status of target
	model.Mutex.Lock()
	h.Step = model.SWEEPED.String()
	utils.Config.DB.Save(&h)
	model.Mutex.Unlock()
}

func workerARPSweep(name string, h *model.Target, folder string, file string) {
	// Get network interface
	iface, err := net.InterfaceByName("eth0") // You might want to make this configurable
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error getting network interface: %v", err))
		return
	}

	// Create ARP scanner
	scanner := NewARPScanner(iface)

	// Parse the network CIDR
	_, network, err := net.ParseCIDR(h.Address + "/24") // Assuming /24 network
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error parsing network: %v", err))
		return
	}

	// Perform ARP scan
	err = scanner.Scan(network)
	if err != nil {
		utils.Config.Log.LogError(fmt.Sprintf("Error during ARP scan: %v", err))
		return
	}

	// Process results
	results := scanner.GetResults()
	for _, result := range results {
		// Save discovered hosts with MAC addresses
		model.AddHostWithMAC(utils.Config.DB, result.IP, "up", model.NEW.String(), result.MAC)
	}

	// Update status of target
	model.Mutex.Lock()
	h.Step = model.SWEEPED.String()
	utils.Config.DB.Save(&h)
	model.Mutex.Unlock()
}
