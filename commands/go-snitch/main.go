package main

import (
	"fmt"
	_ "net"
	"os"
	_ "os/signal"
	_ "syscall"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"

	"github.com/r3boot/go-snitch/lib/dbus"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func main() {
	var (
		dbusClient *dbus.DBusClient
		err        error
	)

	dbusClient = &dbus.DBusClient{}
	if err = dbusClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "dbusClient:", err)
		os.Exit(1)
	}

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()

	packets := nfq.GetPackets()

	rulecache := rules.NewRuleCache("./rules.db")

	for true {
		select {
		case p := <-packets:
			request, err := snitch.GetConnRequest(p.Packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
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

			action, err := dbusClient.GetVerdict(request)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				p.SetVerdict(netfilter.NF_DROP)
				continue
			}

			fmt.Printf("Setting verdict via dbus\n")
			switch action {
			case snitch.DROP_CONN_ALWAYS:
				{
					verdict = netfilter.NF_DROP
				}
			case snitch.ACCEPT_CONN_ALWAYS:
				{
					verdict = netfilter.NF_ACCEPT
				}
			}

			p.SetVerdict(verdict)
			err = rulecache.AddConnRule(request, verdict)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to set rule: %v", err)
			}
		}
	}

}
