package main

import "os/exec"

func openInDefaultBrowser(rawURL string) error {
	return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
}
