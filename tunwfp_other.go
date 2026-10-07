//go:build !amd64

package main

import "net"

type tunDNSGuard struct{ filters int }

func (g *tunDNSGuard) Close() {}

func physDNSServers(uint32) (v4, v6 []net.IP) { return nil, nil }

func newTunDNSGuard(v4, v6 []net.IP) (*tunDNSGuard, error) { return nil, nil }
