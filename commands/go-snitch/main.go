package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"

	"github.com/r3boot/go-snitch/lib/dbus"
	"github.com/r3boot/go-snitch/lib/kernel"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func main() {
	var (
		dbusDaemon *dbus.DBusDaemon
		err        error
	)

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	rulecache := rules.NewRuleCache("./rules.db")
	err = rulecache.Prime()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to prime cache: %v\n", err)
		os.Exit(1)
	}

	dbusDaemon = &dbus.DBusDaemon{}
	if err = dbusDaemon.Connect(rulecache); err != nil {
		fmt.Fprintf(os.Stderr, "dbusDaemon:", err)
		os.Exit(1)
	}

	filter := kernel.NewNetfilter("/usr/bin/iptables", "/usr/bin/ip6tables")
	filter.SetupRules()

	exitSignal := make(chan os.Signal, 1)
	hupSignal := make(chan os.Signal, 1)
	stopHupHandler := make(chan bool, 1)
	signalsCompleted := make(chan bool, 1)

	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-exitSignal
		fmt.Printf("Received signal, exiting...\n")
		filter.CleanupRules()
		signalsCompleted <- true
	}()

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
					fmt.Printf("Reloading ...\n")
					filter.RemoveResolvers()
					filter.AllowResolvers()
				}
			}
		}
	}()

	for true {
		select {
		case <-signalsCompleted:
			{
				os.Exit(0)
			}
		case p := <-packets:
			request, err := snitch.GetConnRequest(p.Packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to get packet details: %v\n", err)
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			verdict, err := rulecache.GetVerdict(request)
			if err != nil {
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			if verdict != netfilter.NF_UNDEF {
				fmt.Printf("Setting verdict via rule\n")
				p.SetVerdict(verdict)
				continue
			}

			action, err := dbusDaemon.GetVerdict(request)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			fmt.Printf("Setting verdict via dbus\n")
			fmt.Printf("Action: %s (%d)\n", rules.DialogVerdictToString(action), action)
			switch action {
			case snitch.DROP_APP_ALWAYS_USER,
				snitch.DROP_APP_ALWAYS_SYSTEM,
				snitch.DROP_CONN_ALWAYS_USER,
				snitch.DROP_CONN_ALWAYS_SYSTEM:
				{
					verdict = netfilter.NF_DROP
					if err = rulecache.AddRule(request, action); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to add rule: %v\n", err)
					}
				}
			case snitch.ACCEPT_APP_ALWAYS_USER,
				snitch.ACCEPT_APP_ALWAYS_SYSTEM,
				snitch.ACCEPT_CONN_ALWAYS_USER,
				snitch.ACCEPT_CONN_ALWAYS_SYSTEM:
				{
					verdict = netfilter.NF_ACCEPT
					if err = rulecache.AddRule(request, action); err != nil {
						fmt.Fprintf(os.Stderr, "Failed to add rule: %v\n", err)
					}
				}
			case snitch.DROP_CONN_ONCE_USER,
				snitch.DROP_CONN_SESSION_USER,
				snitch.DROP_CONN_ONCE_SYSTEM,
				snitch.DROP_CONN_SESSION_SYSTEM,
				snitch.DROP_APP_ONCE_USER,
				snitch.DROP_APP_SESSION_USER,
				snitch.DROP_APP_ONCE_SYSTEM,
				snitch.DROP_APP_SESSION_SYSTEM:
				{
					verdict = netfilter.NF_DROP
				}
			case snitch.ACCEPT_CONN_ONCE_USER,
				snitch.ACCEPT_CONN_SESSION_USER,
				snitch.ACCEPT_CONN_ONCE_SYSTEM,
				snitch.ACCEPT_CONN_SESSION_SYSTEM,
				snitch.ACCEPT_APP_ONCE_USER,
				snitch.ACCEPT_APP_SESSION_USER,
				snitch.ACCEPT_APP_ONCE_SYSTEM,
				snitch.ACCEPT_APP_SESSION_SYSTEM:
				{
					verdict = netfilter.NF_ACCEPT
				}
			default:
				{
					fmt.Fprintf(os.Stderr, "Unknown action!: %d\n", action)
				}
			}

			fmt.Printf("Returning verdict\n")
			p.SetVerdict(verdict)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to set rule: %v", err)
			}
		}
	}
}
