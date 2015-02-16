package main

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

func scp(username, host, file, dest string) error {
	cmd := exec.Command("scp", "-o", "StrictHostKeyChecking=no", "-r", "-C", file, username+"@"+host+":"+dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sshRun(username, host, command string) ([]byte, error) {
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", username+"@"+host,
		"eval '"+command+"'")
	//log.Println(cmd)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func sshRunStdout(username, host, command string) error {
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", username+"@"+host,
		"eval '"+command+"'")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func build(path, goarch, goos string) error {
	cmd := exec.Command("go", "build", "-v", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append([]string{"GOOS=" + goos, "GOARCH=" + goarch}, os.Environ()...)
	return cmd.Run()
}

func timeoutRun(d time.Duration, f func() error) error {
	echan := make(chan error)
	go func() {
		echan <- f()
	}()
	var e error
	select {
	case e = <-echan:
	case <-time.After(d):
		e = errors.New("function timed out")
	}
	return e
}
