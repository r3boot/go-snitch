package systray

import (
	"fmt"
	"os"
	"os/exec"
)

func (st *Systray) initCallbacks() {
	st.popupMenuEnable.ConnectTriggered(st.OnPopupMenuEnable)
	st.popupMenuDisable.ConnectTriggered(st.OnPopupMenuDisable)
	st.popupMenuManage.ConnectTriggered(st.OnPopupMenuManage)
}

func (st *Systray) OnPopupMenuEnable(clicked bool) {
	st.trayicon.SetIcon(st.iconEnabled)
	st.popupMenuEnable.SetDisabled(true)
	st.popupMenuDisable.SetDisabled(false)
}

func (st *Systray) OnPopupMenuDisable(clicked bool) {
	st.trayicon.SetIcon(st.iconDisabled)
	st.popupMenuEnable.SetDisabled(false)
	st.popupMenuDisable.SetDisabled(true)
}

func (st *Systray) OnPopupMenuManage(clicked bool) {
	go func() {
		cmd := exec.Command("go-snitch-manage")

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "st.OnPopupMenuManage: failed to run command: %v", err)
			return
		}

		if err := cmd.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "st.OnPopupMenuManage: failed to wait for command: %v", err)
		}
	}()
}
