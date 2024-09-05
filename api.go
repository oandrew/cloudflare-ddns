package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type RequestProto int

const (
	RequestProtoDefault RequestProto = iota
	RequestProtoIP4
	RequestProtoIP6
)

func getCurrentIP(ipEndpoint string, proto RequestProto) (netip.Addr, error) {
	req, err := http.NewRequest("GET", ipEndpoint, nil)
	if err != nil {
		return netip.Addr{}, errors.Wrap(err, "could not create the request to the IP provider")
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				switch proto {
				case RequestProtoIP4:
					d.FallbackDelay = -1
					if strings.HasPrefix(network, "tcp") {
						network = "tcp4"
					}
					if strings.HasPrefix(network, "udp") {
						network = "udp4"
					}
				case RequestProtoIP6:
					d.FallbackDelay = -1
					if strings.HasPrefix(network, "tcp") {
						network = "tcp6"
					}
					if strings.HasPrefix(network, "udp") {
						network = "udp6"
					}
				}
				return d.DialContext(ctx, network, addr)
			},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, errors.Wrap(err, "current ip http req failed")
	}
	defer res.Body.Close()

	s := bufio.NewScanner(res.Body)
	if !s.Scan() {
		return netip.Addr{}, errors.Wrap(s.Err(), "no output from the provider")
	}

	ip, err := netip.ParseAddr(s.Text())
	if err != nil {
		return netip.Addr{}, errors.Wrap(err, "failed to parse ip")
	}

	if proto == RequestProtoIP4 && !ip.Is4() || proto == RequestProtoIP6 && !ip.Is6() {
		return netip.Addr{}, errors.Errorf("ip addr family mismatch %v", ip)
	}
	return ip, nil
}

func updateRecord(ctx context.Context, api *cloudflare.API, zone, domainName, recordType, content string) error {
	zoneID, err := api.ZoneIDByName(zone)
	if err != nil {
		return errors.Wrap(err, "could not find zone by name")
	}

	dnsRecords, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Name: domainName,
		Type: recordType,
	})
	if err != nil {
		return errors.Wrap(err, "error listing dns records for zone")
	}

	if len(dnsRecords) != 1 {
		return errors.Errorf("Expected to find a single dns record, got %d", len(dnsRecords))
	}

	record := dnsRecords[0]

	if record.Content == content {
		logrus.WithFields(logrus.Fields{
			"name":    record.Name,
			"type":    record.Type,
			"content": record.Content,
		}).Info("no change")
		return nil
	}

	newRecord, err := api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.UpdateDNSRecordParams{
		ID:      record.ID,
		Name:    record.Name,
		Type:    record.Type,
		Content: content,
	})
	if err != nil {
		return errors.Wrap(err, "could not update the DNS record")
	}

	// Log the update.
	logrus.WithFields(logrus.Fields{
		"name":    newRecord.Name,
		"type":    newRecord.Type,
		"content": newRecord.Content,
	}).Info("updated record")
	return nil
}

func UpdateDomain4(ctx context.Context, api *cloudflare.API, zone, domainName, ipEndpoint string) error {
	ip, err := getCurrentIP(ipEndpoint, RequestProtoIP4)
	if err != nil {
		return errors.Wrap(err, "could not get the current IP4 address")
	}
	logrus.WithField("ip", ip).Info("got current IP4 address")
	if err := updateRecord(ctx, api, zone, domainName, "A", ip.String()); err != nil {
		return errors.Wrap(err, "failed to update A record")
	}
	return nil
}

func UpdateDomain6(ctx context.Context, api *cloudflare.API, zone, domainName, ipEndpoint string) error {
	ip, err := getCurrentIP(ipEndpoint, RequestProtoIP6)
	if err != nil {
		return errors.Wrap(err, "could not get the current IP6 address")
	}
	logrus.WithField("ip6", ip).Info("got current IP6 address")
	if err := updateRecord(ctx, api, zone, domainName, "AAAA", ip.String()); err != nil {
		return errors.Wrap(err, "failed to update AAAA record")
	}
	return nil
}
