package main

import (
	"net"
	"strconv"
	"time"
	evs "github.com/cybermaggedon/evs-golang-api"
	ind "github.com/cybermaggedon/indicators"
	"os"
	"log"
	"strings"
	"encoding/binary"
)

// Detector analytic
type Detector struct {
	evs.EventAnalytic
	fsmc *ind.FsmCollection
	indicatorFile string
	lastIndicatorUpdate time.Time
	ch chan *ind.FsmCollection
}

func int32ToIp(ipLong uint32) net.IP {
	ipByte := make([]byte, 4)
	binary.BigEndian.PutUint32(ipByte, ipLong)
	return net.IP(ipByte)
}

func bytesToIp(b []byte) net.IP {
	return net.IP(b)
}

func GetTokens(ev *evs.Event) *[]ind.Token {

	tk := []ind.Token{}

	GetAddresses(ev, &tk)
	GetDns(ev, &tk)
	GetUrl(ev, &tk)
	GetEmail(ev, &tk)

	return &tk

}

func GetDns(ev *evs.Event, tk *[]ind.Token) {
	dns := ev.GetDnsMessage()
	if dns == nil {
		return
	}
	for _, v := range dns.Query {
		*tk = append(*tk, ind.Token{"hostname", v.Name})
	}
	for _, v := range dns.Answer {
		*tk = append(*tk, ind.Token{"hostname", v.Name})
	}
}

func GetUrl(ev *evs.Event, tk *[]ind.Token) {
	if ev.Url != "" {
		*tk = append(*tk, ind.Token{"url", ev.Url})
	}
}

func GetEmail(ev *evs.Event, tk *[]ind.Token) {
	smtp_data := ev.GetSmtpData()
	if smtp_data == nil {
		return
	}

	if smtp_data.From != "" {
		*tk = append(*tk,
			ind.Token{"email", ev.GetSmtpData().From})
	}
	for _, v := range smtp_data.To {
		*tk = append(*tk, ind.Token{"email", v})
	}
}

func GetAddresses(ev *evs.Event, tk *[]ind.Token) {

	for _, addr := range ev.Src {
		if addr.Protocol == evs.Protocol_ipv4 {
			ip := int32ToIp(addr.Address.GetIpv4()).String()
			*tk = append(*tk, ind.Token{"ipv4", ip})
			*tk = append(*tk, ind.Token{"ipv4.src", ip})
		}
		if addr.Protocol == evs.Protocol_ipv6 {
			ip := bytesToIp(addr.Address.GetIpv6()).String()
			*tk = append(*tk, ind.Token{"ipv6", ip})
			*tk = append(*tk, ind.Token{"ipv6.src", ip})
		}
		if addr.Protocol == evs.Protocol_tcp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"tcp", port})
			*tk = append(*tk, ind.Token{"tcp.src", port})
		}
		if addr.Protocol == evs.Protocol_udp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"udp", port})
			*tk = append(*tk, ind.Token{"udp.src", port})
		}
	}

	for _, addr := range ev.Dest {
		if addr.Protocol == evs.Protocol_ipv4 {
			ip := int32ToIp(addr.Address.GetIpv4()).String()
			*tk = append(*tk, ind.Token{"ipv4", ip})
			*tk = append(*tk, ind.Token{"ipv4.dest", ip})
		}
		if addr.Protocol == evs.Protocol_ipv6 {
			ip := bytesToIp(addr.Address.GetIpv6()).String()
			*tk = append(*tk, ind.Token{"ipv6", ip})
			*tk = append(*tk, ind.Token{"ipv6.dest", ip})
		}
		if addr.Protocol == evs.Protocol_tcp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"tcp", port})
			*tk = append(*tk, ind.Token{"tcp.dest", port})
		}
		if addr.Protocol == evs.Protocol_udp {
			port := strconv.Itoa(int(addr.Address.GetPort()))
			*tk = append(*tk, ind.Token{"udp", port})
			*tk = append(*tk, ind.Token{"udp.dest", port})
		}
	}

}

func (d *Detector) LoadIndicators() (*ind.FsmCollection, error) {

	stat, err := os.Stat(d.indicatorFile)
	if err != nil {
		return nil, err
	}
	
	d.lastIndicatorUpdate = stat.ModTime()

	ii, err := ind.LoadIndicatorsFromFile(d.indicatorFile)
	if err != nil {
		return nil, err
	}

	fsmc := ind.CreateFsmCollection(ii)

	log.Printf("%d FSMs created", len(fsmc.Fsms))

	return fsmc, nil

}

func (d *Detector) Reloader() {

	for {

		time.Sleep(5 * time.Second)

		stat, err := os.Stat(d.indicatorFile)
		if err != nil {
			log.Printf("Stat error on indicator file!: %v", err)
			continue
		}

		// If indicator file is unchanged, go back and wait
		if stat.ModTime() == d.lastIndicatorUpdate {
			continue
		}

		log.Print("Loading indicators...")
		fsmc, err := d.LoadIndicators()
		if err != nil {
			log.Printf("Error loading indicators: %v", err)
			return
		}
		log.Print("Indicators loaded.")

		// Pass indicators to chan
		d.ch <- fsmc
		
	}
	
}

// Event handler
func (d *Detector) Event(ev *evs.Event, properties map[string]string) error {

	select {
        case fsmc := <- d.ch:
		d.fsmc = fsmc
		log.Print("Using new indicators.")
	default:
        }

	tokens := GetTokens(ev)

	d.fsmc.Reset()
	for _, v := range *tokens {
		d.fsmc.Update(v)
	}
	d.fsmc.Dump()

	hits := d.fsmc.GetHits()

	for _, v := range hits {
		v.Dump()
	}
	
	d.OutputEvent(ev, properties)

	return nil

}

func main() {

	d := &Detector{}
	d.ch = make(chan *ind.FsmCollection)

	// Plan is to load indicators (may take some time) before touching
	// the queue.
	var ok bool
	d.indicatorFile, ok = os.LookupEnv("INDICATORS")
	if !ok {
		d.indicatorFile = "indicators.json"
	}

	log.Print("Loading indicators...")
	var err error
	d.fsmc, err = d.LoadIndicators()
	if err != nil {
		log.Printf("Error loading indicators: %v", err)
		return
	}
	log.Print("Indicators loaded.")

	go d.Reloader()

	binding, ok := os.LookupEnv("INPUT")
	if !ok {
		binding = "cyberprobe"
	}

	out, ok := os.LookupEnv("ioc")
	if !ok {
		d.Init(binding, []string{}, d)
	} else {
		outarray := strings.Split(out, ",")
		d.Init(binding, outarray, d)
	}

	d.Run()

}

