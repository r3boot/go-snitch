package request

import (
	"fmt"

	"github.com/r3boot/test/lib/ui"
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
	response.Action = ui.ACTION_WHITELIST
	rw.responseChan <- response
}

func (rw *RequestWindow) OnBlockButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Action = ui.ACTION_BLOCK
	rw.responseChan <- response
}

func (rw *RequestWindow) OnAllowButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Action = ui.ACTION_ALLOW
	rw.responseChan <- response
}

func (rw *RequestWindow) OnDenyButtonClicked(clicked bool) {
	rw.Hide()
	response := rw.getValues()
	response.Action = ui.ACTION_DENY
	rw.responseChan <- response
}

func (rw *RequestWindow) OnClose() {
	fmt.Printf("Closing window\n")
	rw.Hide()
}
