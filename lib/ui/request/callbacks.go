package request

import (
	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
	"github.com/r3boot/go-snitch/lib/datastructures"
)

func (rw *RequestWindow) initCallbacks() {
	rw.window.ConnectDestroyQObject(rw.OnClose)
	rw.buttonWhitelist.ConnectClicked(rw.OnWhitelistButtonClicked)
	rw.buttonBlock.ConnectClicked(rw.OnBlockButtonClicked)
	rw.buttonAllow.ConnectClicked(rw.OnAllowButtonClicked)
	rw.buttonDeny.ConnectClicked(rw.OnDenyButtonClicked)
}

func (rw *RequestWindow) OnWhitelistButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Verdict = netfilter.NF_ACCEPT
	response.Action = datastructures.ACTION_WHITELIST
	rw.responseChan <- response
}

func (rw *RequestWindow) OnBlockButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Verdict = netfilter.NF_DROP
	response.Action = datastructures.ACTION_BLOCK
	rw.responseChan <- response
}

func (rw *RequestWindow) OnAllowButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Verdict = netfilter.NF_ACCEPT
	response.Action = datastructures.ACTION_ALLOW
	rw.responseChan <- response
}

func (rw *RequestWindow) OnDenyButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Verdict = netfilter.NF_DROP
	response.Action = datastructures.ACTION_DENY
	rw.responseChan <- response
}

func (rw *RequestWindow) OnClose() {
	rw.Hide()
}
