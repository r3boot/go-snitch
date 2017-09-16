package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/ipc/daemonipc"
	"github.com/r3boot/go-snitch/lib/iptables"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

const (
	D_DEBUG     bool   = false
	D_TIMESTAMP bool   = false
	D_DATABASE  string = "/var/lib/go-snitch.db"
)

var (
	log         *logger.Logger
	nfq         *netfilter.NFQueue
	packetQueue <-chan netfilter.NFPacket
	ruleCache   *rules.RuleCache
	ipc         *daemonipc.DaemonIPCService
	ipt         *iptables.Iptables
	engine      *snitch.Engine

	useDebug     = flag.Bool("d", D_DEBUG, "Use debug output")
	useTimestamp = flag.Bool("t", D_TIMESTAMP, "Use timestamp in output")
	ruleDatabase = flag.String("database", D_DATABASE, "Path to database")
)

func init() {
	var err error

	flag.Parse()

	// Initialize logging framework
	log = logger.NewLogger(*useTimestamp, *useDebug)

	// Initialize Netfilter userspace queue
	nfq, err = netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Fatalf("Failed to initialize netfilter queue: %v", err)
	}

	// Setup packet queue
	packetQueue = nfq.GetPackets()

	// Setup backend database + cache
	ruleCache, err = rules.NewRuleCache(log, *ruleDatabase)
	if err != nil {
		log.Fatalf("Failed to initialize ruleCache: %v", err)
	}

	if err = ruleCache.Prime(); err != nil {
		log.Fatalf("Failed to prime ruleCache: %v", err)
	}

	// Setup DBUS handler + client
	ipc, err = daemonipc.NewDaemonIPCService(log, ruleCache)
	if err != nil {
		log.Fatalf("Failed to initialize DBUS: %v", err)
	}

	// Setup netfilter and default rules
	ipt, err = iptables.NewNetfilter(log)
	if err != nil {
		log.Fatalf("Failed to initialize Netfilter: %v", err)
	}

	err = ipt.SetupRules()
	if err != nil {
		log.Fatalf("Failed to load initial netfilter rules: %v", err)
	}

	// Setup snitch engine
	engine, err = snitch.NewEngine(log)
	if err != nil {
		log.Fatalf("Failed to initialize engine: %v", err)
	}
}

func main() {
	// Setup channels for signal handlers
	exitSignal := make(chan os.Signal, 1)
	hupSignal := make(chan os.Signal, 1)
	stopHupHandler := make(chan bool, 1)
	signalsCompleted := make(chan bool, 1)

	// Disable engine and cleanup rules on exit
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-exitSignal
		log.Infof("Received signal, exiting...")
		engine.Disable()
		ipt.CleanupRules()
		ipt.RemoveResolvers()
		signalsCompleted <- true
	}()

	// Reload resolvers on HUP signal
	signal.Notify(hupSignal, syscall.SIGHUP)
	go func() {
		runHandler := true
		for runHandler {
			select {
			case <-stopHupHandler:
				{
					runHandler = false
				}
			case <-hupSignal:
				{
					log.Infof("Reloading ...")
					ipt.RemoveResolvers()
					ipt.AllowResolvers()
				}
			}
		}
	}()

	// Start packet handling loop
	log.Infof("Snitching packets")
	for {
		select {
		case <-signalsCompleted: // OnExit signal handler completed
			{
				os.Exit(0)
			}
		case p := <-packetQueue: // Received new packet
			// Extract details from packet. If we fail to process this packet
			// in any way, drop it and continue processing.
			request, err := engine.ProcessPacket(p.Packet)
			if err != nil {
				log.Warningf("Dropping packet: %v (%s)", err, engine.DumpPacket(p.Packet))
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			log.Debugf("New %s", request)

			// Check if we have an existing verdict in the rulecache
			verdict, err := ruleCache.GetVerdict(request)
			if err != nil {
				log.Warningf("Error from ruleCache, dropping: %v (%s)", err, engine.DumpPacket(p.Packet))
				engine.DumpPacket(p.Packet)
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			if verdict != netfilter.NF_UNDEF {
				log.Debugf("Setting verdict via rule")
				p.SetVerdict(verdict)
				continue
			}

			// Request a verdict via dbus
			response, err := ipc.GetVerdict(request)
			if err != nil {
				log.Warningf("Error from ipc, dropping: %v (%s)", err, engine.DumpPacket(p.Packet))
				engine.DumpPacket(p.Packet)
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			// Check action to see what we need to do with the packet
			log.Debugf("Setting verdict via ipc")
			if response.Scope == datastructures.SCOPE_FOREVER {
				if err = ruleCache.AddRule(request, response); err != nil {
					log.Warningf("Error from ruleCache: %v", err)
				}
			}

			if response.Verdict == netfilter.NF_UNDEF {
				log.Warningf("Unknown error: dropping packet %s", engine.DumpPacket(p.Packet))
				p.SetVerdict(netfilter.NF_DROP)
			} else {
				p.SetVerdict(response.Verdict)
			}
		}
	}
}
